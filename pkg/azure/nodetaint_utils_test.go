package azure

import (
	"testing"
	"context"

	fake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
    "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckIfTaintExists(t *testing.T) {
	type testCase struct {
		Name string
		node *corev1.Node
		ExpectedOutput bool
	}

	testCases := []testCase{
		{
			Name: "taint-exists",
			node : &corev1.Node{
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "azure-firewall-policy",
							Value:  "update-pending",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
				},
			},
			ExpectedOutput: true,
		},
		{
			Name: "taint-doesn't-exist",
			node : &corev1.Node{
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{},
				},
			},
			ExpectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			output := CheckIfTaintExists(tc.node);
			if tc.ExpectedOutput != output {
				t.Errorf("Expected %t, but got: %t", tc.ExpectedOutput, output);
			} 
		})
	}
}

func TestCheckIfNodeNotReady(t *testing.T) {
	type testCase struct {
		Name string
		node *corev1.Node
		ExpectedOutput bool
	}

	testCases := []testCase{
		{
			Name: "node-not-ready",
			node : &corev1.Node{
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "node.cloudprovider.kubernetes.io/uninitialized",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
				},
			},
			ExpectedOutput: true,
		},
		{
			Name: "node-ready",
			node : &corev1.Node{
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{},
				},
			},
			ExpectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			output := CheckIfNodeNotReady(tc.node);
			if tc.ExpectedOutput != output {
				t.Errorf("Expected %t, but got: %t", tc.ExpectedOutput, output);
			} 
		})
	}
}

func TestRemoveTaints(t *testing.T) {
	obj := []client.Object{}
	client := fake.NewClientBuilder().WithObjects(obj...).Build();

    node := &corev1.Node{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-node",
        },
        Spec: corev1.NodeSpec{
            Taints: []corev1.Taint{
				{
					Key:    "azure-firewall-policy",
					Value:  "update-pending",
					Effect: corev1.TaintEffectNoSchedule,
				},
			},
        },
    }

    err := client.Create(context.Background(), node)
    if err!=nil{
		t.Errorf("Expected no error, but got: %v", err)
	}

    az := &azClient{
        client: client,
    }

    az.RemoveTaints(context.Background(), node)

    updatedNode := &corev1.Node{}
    err = client.Get(context.Background(), types.NamespacedName{Name: "test-node"}, updatedNode)
    if err!=nil{
		t.Errorf("Expected no error, but got: %v", err)
	}

	if CheckIfTaintExists(updatedNode) != false {
		t.Errorf("Expected %t, but got: %t", false, true);
	}
}

func TestAddTaints(t *testing.T) {
	obj := []client.Object{};
    client:= fake.NewClientBuilder().WithObjects(obj...).Build();

    node := &corev1.Node{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-node",
        },
    }

    err := client.Create(context.Background(), node)
	if err!=nil{
		t.Errorf("Expected no error, but got: %v", err);
	}

    az := &azClient{
        client: client,
    }

    req := ctrl.Request{
        NamespacedName: types.NamespacedName{
            Name: "test-node",
        },
    }

    az.AddTaints(context.Background(), req)

    updatedNode := &corev1.Node{}
    err = client.Get(context.Background(), req.NamespacedName, updatedNode)

	if err!=nil{
		t.Errorf("Expected no error, but got: %v", err)
	}

	if CheckIfTaintExists(updatedNode) != true {
		t.Errorf("Expected %t, but got: %t", true, false);
	}
}