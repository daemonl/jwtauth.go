package jwtauth

import "sync"

type statusRunner struct {
	isDone bool
	chDone chan struct{}
	lock   sync.Mutex
}

func (sr *statusRunner) Done() {
	sr.lock.Lock()
	defer sr.lock.Unlock()
	if sr.isDone {
		return
	}
	sr.isDone = true
	close(sr.chDone)
}

// AnyAllWaitGroup is like a WaitGroup but also with the ability to wait for
// any single Done() to have been called
type AnyAllWaitGroup struct {
	all sync.WaitGroup
	any *statusRunner
}

func (sc *AnyAllWaitGroup) Child() *statusRunner {
	sc.all.Add(1)
	runner := &statusRunner{
		chDone: make(chan struct{}),
	}
	go func() {
		<-runner.chDone
		sc.all.Done()
		sc.any.Done()
	}()

	return runner
}

func NewAnyAllWaitGroup() *AnyAllWaitGroup {
	return &AnyAllWaitGroup{
		any: &statusRunner{
			chDone: make(chan struct{}),
		},
	}
}

func (sc *AnyAllWaitGroup) WaitAny() {
	<-sc.any.chDone
}

func (sc *AnyAllWaitGroup) WaitAll() {
	sc.all.Wait()
}
