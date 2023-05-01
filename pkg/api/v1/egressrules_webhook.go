/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"errors"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var egressruleslog = logf.Log.WithName("egressrules-resource")

func (r *Egressrules) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-egress-azure-firewall-egress-controller-io-v1-egressrules,mutating=false,failurePolicy=fail,sideEffects=None,groups=egress.azure-firewall-egress-controller.io,resources=egressrules,verbs=create;update,versions=v1,name=vegressrules.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &Egressrules{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Egressrules) ValidateCreate() error {
	egressruleslog.Info("validate create", "name", r.Name)

	return r.validateFields()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Egressrules) ValidateUpdate(old runtime.Object) error {
	egressruleslog.Info("validate update", "name", r.Name)

	return r.validateFields()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Egressrules) ValidateDelete() error {
	egressruleslog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}

func (r *Egressrules) validateFields() error {
	for _, egressrule := range r.Spec.EgressRules {
		for _, rule := range egressrule.Rules {
			if rule.RuleType == "Application" {
				if rule.TargetFqdns == nil {
					return errors.New("Target Fqdns field is mandatory field for Application rule in")
				} else if rule.DestinationAddresses != nil || rule.DestinationFqdns != nil || rule.DestinationPorts != nil {
					return errors.New("Fields DestinationAddresses/DestinationFqdns/DestinationPorts are not supported by Application Rule")
				}
			} else {
				if rule.TargetFqdns != nil || rule.TargetUrls != nil {
					return errors.New("Fields TargetFqdns/TargetUrls are not supported by Network Rule")
				} else if rule.DestinationAddresses != nil && rule.DestinationFqdns != nil {
					return errors.New("Multiple destination types cannot provided")
				} else if rule.DestinationAddresses == nil && rule.DestinationFqdns == nil {
					return errors.New("One destination type should be provided")
				} else if rule.DestinationPorts == nil {
					return errors.New("Destination port missing")
				}
			}
		}
	}
	return nil
}
