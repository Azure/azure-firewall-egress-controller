// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package controllers

import (
	"context"
	"fmt"
	"time"

	//egressv1 "azure-firewall-egress-controller.io/aks-egress/api/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

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
	q.jobs <- job
}

func (j Job) Run() error {
	fmt.Printf("Updating policy.......... : %#v\n\n", j.Request)
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
			fmt.Printf("Context cancelled ... : %#v\n\n", w.Queue.ctx.Err())
			return true
		// if job received.
		case job := <-w.Queue.jobs:
			time.Sleep(5 * time.Second)
			err := job.Run()
			if err != nil {
				fmt.Printf("Err in DoWork ... : %#v\n\n", err)
				continue
			}
		}
	}
}
