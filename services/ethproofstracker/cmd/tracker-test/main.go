package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/ethproofstracker/standard"
	"github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/rs/zerolog"
)

// CapturingScheduler intercepts job scheduling
type CapturingScheduler struct {
	jobs map[string]scheduler.JobFunc
}

func (s *CapturingScheduler) ScheduleJob(_ context.Context, _ string, name string, _ time.Time, job scheduler.JobFunc) error {
	s.jobs[name] = job
	return nil
}

func (s *CapturingScheduler) SchedulePeriodicJob(_ context.Context, _ string, name string, _ scheduler.RuntimeFunc, job scheduler.JobFunc) error {
	fmt.Printf("[Test] Scheduled periodic job: %s\n", name)
	s.jobs[name] = job
	return nil
}

func (s *CapturingScheduler) RunJob(_ context.Context, name string) error {
	if job, ok := s.jobs[name]; ok {
		fmt.Printf("[Test] Running job manually: %s\n", name)
		job(context.Background())
		return nil
	}
	return fmt.Errorf("job not found: %s", name)
}

func (s *CapturingScheduler) JobExists(_ context.Context, _ string) bool { return false }
func (s *CapturingScheduler) ListJobs(_ context.Context) []string       { return nil }
func (s *CapturingScheduler) RunJobIfExists(_ context.Context, _ string) {}
func (s *CapturingScheduler) CancelJob(_ context.Context, _ string) error { return nil }
func (s *CapturingScheduler) CancelJobIfExists(_ context.Context, _ string) {}
func (s *CapturingScheduler) CancelJobs(_ context.Context, _ string) {}

// MockChainTime
type MockChainTime struct {
	epoch phase0.Epoch
}

func (m *MockChainTime) GenesisTime() time.Time                       { return time.Now() }
func (m *MockChainTime) StartOfSlot(slot phase0.Slot) time.Time       { return time.Now() }
func (m *MockChainTime) StartOfEpoch(epoch phase0.Epoch) time.Time    { return time.Now() }
func (m *MockChainTime) CurrentSlot() phase0.Slot                     { return phase0.Slot(m.epoch * 32) }
func (m *MockChainTime) CurrentEpoch() phase0.Epoch                   { return m.epoch }
func (m *MockChainTime) SlotToEpoch(slot phase0.Slot) phase0.Epoch    { return phase0.Epoch(slot / 32) }
func (m *MockChainTime) FirstSlotOfEpoch(epoch phase0.Epoch) phase0.Slot { return phase0.Slot(epoch * 32) }
func (m *MockChainTime) HardForkEpoch(ctx context.Context, hardForkName string) phase0.Epoch { return 0 }

// MockBeaconBlockRootProvider
type MockBeaconBlockRootProvider struct {
	root phase0.Root
}

func (m *MockBeaconBlockRootProvider) BeaconBlockRoot(ctx context.Context, opts *api.BeaconBlockRootOpts) (*api.Response[*phase0.Root], error) {
	return &api.Response[*phase0.Root]{Data: &m.root}, nil
}

func fetchHeadELHash(endpoint string) (phase0.Root, phase0.Epoch, error) {
	url := fmt.Sprintf("%s/eth/v2/beacon/blocks/head", strings.TrimRight(endpoint, "/"))
	resp, err := http.Get(url)
	if err != nil {
		return phase0.Root{}, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return phase0.Root{}, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return phase0.Root{}, 0, fmt.Errorf("API status %d: %s", resp.StatusCode, string(body))
	}

	// Use generic map to find execution_payload.block_hash robustly
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return phase0.Root{}, 0, err
	}

	// Navigate to message
	innerData, ok := data["data"].(map[string]interface{})
	if !ok {
		return phase0.Root{}, 0, fmt.Errorf("missing 'data' field")
	}
	message, ok := innerData["message"].(map[string]interface{})
	if !ok {
		return phase0.Root{}, 0, fmt.Errorf("missing 'message' field")
	}

	// Parse Slot
	slotStr, _ := message["slot"].(string)
	slotInt, _ := strconv.ParseUint(slotStr, 10, 64)
	epoch := phase0.Epoch(slotInt / 32)

	// Parse EL Hash
	bodyField, _ := message["body"].(map[string]interface{})
	payload, _ := bodyField["execution_payload"].(map[string]interface{})
	elHashStr, _ := payload["block_hash"].(string)

	if elHashStr == "" {
		return phase0.Root{}, 0, fmt.Errorf("no execution payload block hash found")
	}

	if strings.HasPrefix(elHashStr, "0x") {
		elHashStr = elHashStr[2:]
	}
	elHashBytes, err := hex.DecodeString(elHashStr)
	if err != nil {
		return phase0.Root{}, 0, fmt.Errorf("invalid hex hash: %v", err)
	}
	if len(elHashBytes) != 32 {
		return phase0.Root{}, 0, fmt.Errorf("invalid hash length: %d", len(elHashBytes))
	}

	var root phase0.Root
	copy(root[:], elHashBytes)

	return root, epoch, nil
}

func main() {
	beaconNodePtr := flag.String("beacon-node", "", "URL of beacon node to fetch head block from")
	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.New(os.Stdout).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	fmt.Println("Starting Ethproofs Tracker Test Client...")

	ctx := context.Background()
	monitor := null.New()

	currentEpoch := phase0.Epoch(300000)
	currentRoot := phase0.Root{0x01, 0x02, 0x03, 0x04} 

	if *beaconNodePtr != "" {
		fmt.Printf("[Test] Fetching head block info from %s...\n", *beaconNodePtr)
		root, epoch, err := fetchHeadELHash(*beaconNodePtr)
		if err != nil {
			fmt.Printf("[Test] Failed to fetch from beacon node: %v\n", err)
			os.Exit(1)
		}
		currentRoot = root
		currentEpoch = epoch
		fmt.Printf("[Test] Fetched Head: Epoch=%d, EL_Hash=%#x\n", currentEpoch, currentRoot)
		
		fmt.Println("[Test] Waiting 12 seconds for proof generation...")
		time.Sleep(12 * time.Second)
	}

	chainTime := &MockChainTime{epoch: currentEpoch}
	rootProvider := &MockBeaconBlockRootProvider{root: currentRoot}
	sched := &CapturingScheduler{jobs: make(map[string]scheduler.JobFunc)}

	fmt.Println("[Test] Initializing Service (Fetching VKeys)...")
	tracker, err := standard.New(ctx,
		standard.WithMonitor(monitor),
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithChainTime(chainTime),
		standard.WithBeaconBlockRootProvider(rootProvider),
		standard.WithScheduler(sched),
		standard.WithPollInterval(time.Second),
	)

	if err != nil {
		panic(err)
	}

	fmt.Println("[Test] Service Initialized.")
	
	if tracker == nil {
		panic("Tracker is nil")
	}

	fmt.Println("[Test] Triggering Poll Cycle...")
	if err := sched.RunJob(ctx, "Poll ethproofs.org"); err != nil {
		fmt.Printf("Failed to run poll job: %v\n", err)
	}

	fmt.Println("[Test] Done.")
}
