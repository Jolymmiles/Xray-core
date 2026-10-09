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
// and returns how many clients remain in it. The pass may overlap the
// background cleaner, which is safe for keys nothing dials again, such as
// those of a stopped instance.
func CleanPooledClients() int {
	pool := processPool()
	pool.cleanOnce()
	pool.RLock()
	defer pool.RUnlock()
	return len(pool.m)
}
