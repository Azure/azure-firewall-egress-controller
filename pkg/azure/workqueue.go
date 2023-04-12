// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package controllers

import (
	"context"
	"time"

	//egressv1 "github.com/Azure/azure-firewall-egress-controller/api/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

var jobsInQueue = make(map[string]bool)

type Queue struct {
	name   string
	jobs   chan Job
	ctx    context.Context
	cancel context.CancelFunc
}

// Job - holds logic to perform some operations during queue execution.
type Job struct {
	Request  ctrl.Request
	ctx      context.Context
	AzClient AzClient
}

type Worker struct {
	Queue *Queue
}

// NewQueue instantiates new queue.
func NewQueue(name string) *Queue {
	ctx, cancel := context.WithCancel(context.Background())

	return &Queue{
		jobs:   make(chan Job),
		name:   name,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (q *Queue) AddJob(job Job) {
	resourceName := job.Request.NamespacedName.Name
	if jobsInQueue[resourceName] == false {
		jobsInQueue[resourceName] = true
		q.jobs <- job
	}
}

func (j Job) Run() error {
	resourceName := j.Request.NamespacedName.Name
	jobsInQueue[resourceName] = false
	klog.Info("Firewall Policy update event triggered for the reconcile request:", j.Request)
	j.AzClient.getEgressRules(j.ctx, j.Request)
	return nil
}

func NewWorker(queue *Queue) *Worker {
	return &Worker{
		Queue: queue,
	}
}

// DoWork processes jobs from the queue (jobs channel).
func (w *Worker) DoWork() bool {
	for {
		select {
		case <-w.Queue.ctx.Done():
			klog.Error("Context cancelled ... :", w.Queue.ctx.Err())
			return true
		// if job received.
		case job := <-w.Queue.jobs:
			time.Sleep(5 * time.Second)
			err := job.Run()
			if err != nil {
				klog.Error("Err in DoWork ... :", err)
				continue
			}
		}
	}
}
