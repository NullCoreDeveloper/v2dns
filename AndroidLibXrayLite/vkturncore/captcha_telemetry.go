package vkturncore

import (
	"encoding/json"
	"time"
)

const (
	sensorDelayDefault = 100 * time.Millisecond
	sensorDelayFloor   = 20 * time.Millisecond
	sensorDelayCeil    = 2 * time.Second
	sensorTicksMax     = 600

	emptyTelemetryArray = "[]"
)

type sensorConfig struct {
	delay time.Duration
}

func defaultSensorConfig() sensorConfig {
	return sensorConfig{delay: sensorDelayDefault}
}

func parseSensorConfig(raw map[string]any) sensorConfig {
	cfg := defaultSensorConfig()
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return cfg
	}
	if ms, hasDelay := resp["sensors_delay"].(float64); hasDelay && ms > 0 {
		cfg.delay = min(max(time.Duration(ms)*time.Millisecond, sensorDelayFloor), sensorDelayCeil)
	}
	return cfg
}

type captchaAnalytics struct {
	connDownlink []float64
}

func (a captchaAnalytics) fields() [][2]string {
	return [][2]string{
		{"accelerometer", emptyTelemetryArray},
		{"gyroscope", emptyTelemetryArray},
		{"motion", emptyTelemetryArray},
		{"cursor", emptyTelemetryArray},
		{"taps", emptyTelemetryArray},
		{"connectionRtt", emptyTelemetryArray},
		{"connectionDownlink", downlinkArray(a.connDownlink)},
	}
}

func downlinkArray(values []float64) string {
	if len(values) == 0 {
		return emptyTelemetryArray
	}
	data, err := json.Marshal(values)
	if err != nil {
		return emptyTelemetryArray
	}
	return string(data)
}

func buildAnalytics(cfg sensorConfig, downlink float64, elapsed time.Duration) captchaAnalytics {
	ticks := ticksIn(elapsed, cfg.delay)
	if ticks == 0 {
		return captchaAnalytics{}
	}
	return captchaAnalytics{connDownlink: sampleDownlink(downlink, ticks)}
}

func ticksIn(d time.Duration, delay time.Duration) int {
	if d <= 0 || delay <= 0 {
		return 0
	}
	return min(int(d/delay), sensorTicksMax)
}

const (
	downlinkMinSteps = 160 // 8.0
	downlinkMaxSteps = 200 // 10.0
)

func sessionDownlink() float64 {
	steps := downlinkMinSteps + randIntN(downlinkMaxSteps-downlinkMinSteps+1)
	return float64(steps*5) / 100
}

func sampleDownlink(value float64, ticks int) []float64 {
	if ticks <= 0 {
		return nil
	}
	out := make([]float64, ticks)
	for i := range out {
		out[i] = value
	}
	return out
}
