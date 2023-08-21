package azure

import (
	"testing"
	"reflect"
	"github.com/Azure/go-autorest/autorest/to"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckIfLabelExists(t *testing.T) {
	key := "key";
	value:= "value";
	labels:= map[string]string{"key":"value","key1":"value1"};

	labelExists := checkIfLabelExists(key,value,labels);

	if labelExists != true {
		t.Errorf("Expected %t, but got: %t", true, false);
	}
}

func TestUnique(t *testing.T) {
	arr := []string{"a","a","b","c","b"};
	expected := []string{"a","b","c"};

	uniqueElements := unique(arr);

	if len(expected)!=len(uniqueElements) {
		t.Errorf("element counts are different: Expected %d but got: %d", len(expected), len(uniqueElements));
	}

	if !reflect.DeepEqual(uniqueElements, expected) {
		t.Errorf("expected %s, but got %s", expected, uniqueElements);
	}
}

func TestCheckIfElementsPresentInArray(t *testing.T) {
	type testCase struct {
		Name string
		arr1 []*string
		arr2 []*string
		ExpectedOutput bool
	}

	testCases := []testCase{
		{
			Name: "new-element-not-found",
			arr1: []*string{to.StringPtr("string1"),to.StringPtr("string2"),to.StringPtr("string3")},
			arr2: []*string{to.StringPtr("string1"),to.StringPtr("string3"),to.StringPtr("string2")},
			ExpectedOutput: false,
		},
		{
			Name: "new-element-found",
			arr1: []*string{to.StringPtr("string1"),to.StringPtr("string2"),to.StringPtr("string3"),to.StringPtr("string4")},
			arr2: []*string{to.StringPtr("string1"),to.StringPtr("string3"),to.StringPtr("string2")},
			ExpectedOutput: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			output := checkIfElementsPresentInArray(tc.arr1,tc.arr2);
			if tc.ExpectedOutput != output {
				t.Errorf("Expected %t, but got: %t", tc.ExpectedOutput, output);
			} 
		})
	}
}

func TestGetSourceAddressesByNodeLabels(t *testing.T) {
	nodeList := corev1.NodeList{
		Items: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
					Labels: map[string]string{
						"env": "production",
					},
				},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionTrue,
						},
					},
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.1.1",
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
					Labels: map[string]string{
						"env": "development",
					},
				},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionFalse,
						},
					},
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.1.2",
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
					Labels: map[string]string{
						"env": "development",
					},
				},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionFalse,
						},
					},
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.1.3",
						},
					},
				},
			},
		},
	}

	expected := []*string{to.StringPtr("192.168.1.2"),to.StringPtr("192.168.1.3")};

	sourceAddress := getSourceAddressesByNodeLabels("env", "development", nodeList);

	if !reflect.DeepEqual(sourceAddress, expected) {
		t.Errorf("expected %v, but got %v", expected, sourceAddress);
	}
}