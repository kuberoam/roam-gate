package policy

import (
	"context"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/store"
)

// EKS maps IAM principals to Kubernetes users and groups in the aws-auth
// ConfigMap. For an "aws" binding Gate adds an entry mapping the role/user to
// the group roam:aws:<binding ID>, which the binding's RBAC grants to.
//
// Gate only ever adds, changes or removes entries whose username starts with
// "roam:aws:" — entries anyone else wrote are left exactly as they are.
// (Clusters that use EKS access entries instead of aws-auth are configured
// from Roam with AWS credentials; Gate has no AWS access of its own.)

const (
	awsAuthNamespace = "kube-system"
	awsAuthName      = "aws-auth"
	awsPrefix        = "roam:aws:"
)

// AWSGroup is the Kubernetes group an aws binding grants to.
func AWSGroup(bindingID string) string { return awsPrefix + bindingID }

var arnRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:(role|user)/(.+)$`)

// parseARN accepts IAM role and user ARNs. aws-auth matches roles without a
// path, so a role's path is dropped.
func parseARN(arn string) (kind, normalized string, err error) {
	m := arnRe.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return "", "", msg.New(msg.ARNInvalid)
	}
	if m[1] == "role" {
		name := m[2][strings.LastIndexByte(m[2], '/')+1:]
		return "role", strings.SplitN(arn, ":role/", 2)[0] + ":role/" + name, nil
	}
	return "user", strings.TrimSpace(arn), nil
}

type mapEntry struct {
	RoleARN  string   `json:"rolearn,omitempty"`
	UserARN  string   `json:"userarn,omitempty"`
	Username string   `json:"username"`
	Groups   []string `json:"groups,omitempty"`
}

func (r *Reconciler) reconcileAWSAuth(ctx context.Context, bindings []*store.Binding, note func(id, obj string, err error)) error {
	var aws []*store.Binding
	for _, b := range bindings {
		if b.SubjectKind == store.SubjectAWS {
			aws = append(aws, b)
		}
	}
	cms := r.kc.Core.ConfigMaps(awsAuthNamespace)
	cm, err := cms.Get(ctx, awsAuthName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		for _, b := range aws {
			note(b.ID, "", msg.New(msg.AWSAuthMissing))
		}
		return nil
	}
	if apierrors.IsForbidden(err) && len(aws) == 0 {
		// The chart only grants aws-auth access when EKS support is on.
		return nil
	}
	if err != nil {
		if apierrors.IsForbidden(err) {
			err = msg.New(msg.AWSAuthForbidden)
		}
		for _, b := range aws {
			note(b.ID, "", msg.Wrap(msg.AWSAuthRead, err))
		}
		return err
	}
	var roles, users []mapEntry
	parseErr := yaml.Unmarshal([]byte(cm.Data["mapRoles"]), &roles)
	if parseErr == nil {
		parseErr = yaml.Unmarshal([]byte(cm.Data["mapUsers"]), &users)
	}
	if parseErr != nil {
		err := msg.Wrap(msg.AWSAuthInvalid, parseErr)
		for _, b := range aws {
			note(b.ID, "", err)
		}
		return err
	}
	mine := func(e mapEntry) bool { return strings.HasPrefix(e.Username, awsPrefix) }
	newRoles := slices.DeleteFunc(slices.Clone(roles), mine)
	newUsers := slices.DeleteFunc(slices.Clone(users), mine)
	for _, b := range aws {
		kind, arn, err := parseARN(b.Subject)
		if err != nil {
			note(b.ID, "", err)
			continue
		}
		e := mapEntry{Username: awsPrefix + b.ID + ":{{SessionName}}", Groups: []string{AWSGroup(b.ID)}}
		if kind == "role" {
			e.RoleARN = arn
			newRoles = append(newRoles, e)
		} else {
			e.UserARN, e.Username = arn, awsPrefix+b.ID
			newUsers = append(newUsers, e)
		}
		note(b.ID, "ConfigMap/kube-system/aws-auth", nil)
	}
	if slices.EqualFunc(roles, newRoles, sameEntry) && slices.EqualFunc(users, newUsers, sameEntry) {
		return nil
	}
	if err := setYAML(cm, "mapRoles", newRoles); err != nil {
		return err
	}
	if err := setYAML(cm, "mapUsers", newUsers); err != nil {
		return err
	}
	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		for _, b := range aws {
			note(b.ID, "", msg.Wrap(msg.AWSAuthUpdate, err))
		}
		return err
	}
	return nil
}

func sameEntry(a, b mapEntry) bool {
	return a.RoleARN == b.RoleARN && a.UserARN == b.UserARN && a.Username == b.Username && slices.Equal(a.Groups, b.Groups)
}

func setYAML(cm *corev1.ConfigMap, key string, v []mapEntry) error {
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	if len(v) == 0 {
		delete(cm.Data, key)
		return nil
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	cm.Data[key] = string(b)
	return nil
}
