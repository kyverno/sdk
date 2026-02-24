package globalcontext

type Entry interface {
	Get(projection string) (any, error)
	Stop()
}

type ContextMock struct {
	GetGlobalReferenceFunc func(string, string) (any, error)
}

func (mock *ContextMock) GetGlobalReference(n, p string) (any, error) {
	return mock.GetGlobalReferenceFunc(n, p)
}

type MockGctxStore struct {
	Data map[string]Entry
}

func (m *MockGctxStore) Get(name string) (Entry, bool) {
	entry, ok := m.Data[name]
	return entry, ok
}

func (m *MockGctxStore) Set(name string, data Entry) {
	if m.Data == nil {
		m.Data = make(map[string]Entry)
	}
	m.Data[name] = data
}

type MockEntry struct {
	Data any
	Err  error
}

func (m *MockEntry) Get(_ string) (any, error) {
	return m.Data, m.Err
}

func (m *MockEntry) Stop() {}
