package hysteria

// processPool returns the process-wide client pool that Dial uses, creating
// it as Dial does.
func processPool() *clientManager {
	initmanager.Do(func() {
		manager = &clientManager{
			m: make(map[dialerConf]*client),
		}
		go manager.clean()
	})
	return manager
}

// CleanPooledClients runs one cleaner pass over the process-wide client pool
// and returns the pool size after it. The pass may overlap the background
// cleaner and dials; a client added after the pass took its snapshot stays
// in the pool until a later pass.
func CleanPooledClients() int {
	pool := processPool()
	pool.cleanOnce()
	pool.RLock()
	defer pool.RUnlock()
	return len(pool.m)
}
