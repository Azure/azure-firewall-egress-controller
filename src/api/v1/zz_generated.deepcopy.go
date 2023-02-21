//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Egressrules) DeepCopyInto(out *Egressrules) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Egressrules.
func (in *Egressrules) DeepCopy() *Egressrules {
	if in == nil {
		return nil
	}
	out := new(Egressrules)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Egressrules) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EgressrulesList) DeepCopyInto(out *EgressrulesList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Egressrules, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EgressrulesList.
func (in *EgressrulesList) DeepCopy() *EgressrulesList {
	if in == nil {
		return nil
	}
	out := new(EgressrulesList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *EgressrulesList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EgressrulesSpec) DeepCopyInto(out *EgressrulesSpec) {
	*out = *in
	if in.SourceAddress != nil {
		in, out := &in.SourceAddress, &out.SourceAddress
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make([]map[string]string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = make(map[string]string, len(*in))
				for key, val := range *in {
					(*out)[key] = val
				}
			}
		}
	}
	if in.PodSelector != nil {
		in, out := &in.PodSelector, &out.PodSelector
		*out = make([]map[string]string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = make(map[string]string, len(*in))
				for key, val := range *in {
					(*out)[key] = val
				}
			}
		}
	}
	if in.DestinationAddresses != nil {
		in, out := &in.DestinationAddresses, &out.DestinationAddresses
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DestinationPorts != nil {
		in, out := &in.DestinationPorts, &out.DestinationPorts
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DestinationFqdns != nil {
		in, out := &in.DestinationFqdns, &out.DestinationFqdns
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TargetFqdns != nil {
		in, out := &in.TargetFqdns, &out.TargetFqdns
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TargetUrls != nil {
		in, out := &in.TargetUrls, &out.TargetUrls
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Protocol != nil {
		in, out := &in.Protocol, &out.Protocol
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EgressrulesSpec.
func (in *EgressrulesSpec) DeepCopy() *EgressrulesSpec {
	if in == nil {
		return nil
	}
	out := new(EgressrulesSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EgressrulesStatus) DeepCopyInto(out *EgressrulesStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EgressrulesStatus.
func (in *EgressrulesStatus) DeepCopy() *EgressrulesStatus {
	if in == nil {
		return nil
	}
	out := new(EgressrulesStatus)
	in.DeepCopyInto(out)
	return out
}