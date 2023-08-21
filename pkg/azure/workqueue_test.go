package azure

import (
	"testing"
	"context"

	fake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestAddJob(t *testing.T) {
	mockRequest := ctrl.Request {
		NamespacedName: client.ObjectKey {
			Name:      "example-pod",
			Namespace: "default",
		},
	}

	obj := []client.Object{}
	ctx, cancel := context.WithCancel(context.Background());

	buffSize := 10
	queue := &Queue {
		jobs: make(chan Job, buffSize),
		name: "testqueue",
		ctx: ctx,
		cancel: cancel,
	}

	az:= &azClient {
		client: fake.NewClientBuilder().WithObjects(obj...).Build(),
		queue: queue,
		ctx: context.TODO(),
	}

	job := Job {
		Request: mockRequest,
		ctx: az.ctx,
		AzClient: az,
	}

	az.queue.AddJob(job);
	if len(az.queue.jobs) == 0 {
		t.Errorf("Expected length %d, but got: %d", 1, 0);
	}
}

func TestDrainChan(t *testing.T) {
	mockRequest := ctrl.Request {
		NamespacedName: client.ObjectKey {
			Name:      "example-pod",
			Namespace: "default",
		},
	}

	obj := []client.Object{}
	ctx, cancel := context.WithCancel(context.Background());

	buffSize := 10
	counter := int64(0)
	queue := &Queue {
		jobs: make(chan Job, buffSize),
		name: "testqueue",
		ctx: ctx,
		cancel: cancel,
	}

	az:= &azClient {
		client: fake.NewClientBuilder().WithObjects(obj...).Build(),
		queue: queue,
		ctx: context.TODO(),
	}

	worker := &Worker {
		Queue: queue,
		client: az.client,
	}

	job := Job {
		Request: mockRequest,
		ctx: az.ctx,
		AzClient: az,
	}

	Fill:
			for {
				select {
				case az.queue.jobs <- job:
					counter++
				default:
					break Fill
				}
			}

	if int64(len(az.queue.jobs)) != counter {
		t.Errorf("Expected length %d, but got: %d", counter, int64(len(az.queue.jobs)));
	}

	worker.drainChan(job);

	if len(az.queue.jobs) != 0 {
		t.Errorf("Expected length %d, but got: %d", 0, len(az.queue.jobs));
	}
}