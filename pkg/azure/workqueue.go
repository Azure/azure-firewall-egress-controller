// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"context"
	"sync"
	"time"

	//egressv1 "github.com/Azure/azure-firewall-egress-controller/api/v1"
	"github.com/orcaman/concurrent-map/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const minTimeBetweenUpdates = 1 * time.Second

var jobsInQueue = cmap.New[bool]()
var mutex sync.Mutex

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
	Queue  *Queue
	client client.Client
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

	alreadyExists, ok := jobsInQueue.Get(resourceName)
	if ok && alreadyExists {
		return
	}
	jobsInQueue.Set(resourceName, true)
	q.jobs <- job
}

func (j Job) Run(nodesWithFwTaint []*corev1.Node) error {
	klog.Info("Processing request: ", j.Request)
	j.AzClient.processRequest(j.ctx, j.Request, nodesWithFwTaint)
	return nil
}

func NewWorker(queue *Queue, client client.Client) *Worker {
	return &Worker{
		Queue:  queue,
		client: client,
	}
}

func (w *Worker) drainChan(defaultEvent Job) []*corev1.Node {
	var nodesWithFwTaint []*corev1.Node
	c := 0
	for {
		select {
		case event := <-w.Queue.jobs:
			resourceName := event.Request.NamespacedName.Name
			jobsInQueue.Set(resourceName, false)
			c = c + 1
			node := &corev1.Node{}
			if err := w.client.Get(event.ctx, event.Request.NamespacedName, node); err == nil {
				if CheckIfTaintExists(node) {
					nodesWithFwTaint = append(nodesWithFwTaint, node)
				}
			}
		default:
			klog.Infof("Draining %d events from work channel", c)
			return nodesWithFwTaint
		}
	}
}

// DoWork processes jobs from the queue (jobs channel).
func (w *Worker) DoWork() bool {
	lastUpdate := time.Now().Add(-1 * time.Second)
	klog.Info("Worker started")
	for {
		select {
		case <-w.Queue.ctx.Done():
			klog.Error("Context cancelled ... :", w.Queue.ctx.Err())
			return true
		// if job received.
		case job := <-w.Queue.jobs:

			resourceName := job.Request.NamespacedName.Name
			jobsInQueue.Set(resourceName, false)

			since := time.Since(lastUpdate)
			if since < minTimeBetweenUpdates {
				sleep := minTimeBetweenUpdates - since
				klog.Infof("[worker] It has been %+v since last update; Sleeping for %+v before next update", since, sleep)
				time.Sleep(sleep)
			}

			nodesWithFwTaint := w.drainChan(job)

			err := job.Run(nodesWithFwTaint)
			if err != nil {
				klog.Error("Err in DoWork ... :", err)
				continue
			}

			lastUpdate = time.Now()
		}
	}
}
