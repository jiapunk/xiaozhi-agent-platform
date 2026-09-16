package s3camdev

import "testing"

func TestNativeXiaozhiToolCatalogExposesDeviceCapabilities(t *testing.T) {
	session := newDeviceSession(&Server{}, nil, "native-tools")
	session.setTools([]string{
		"self.get_device_status",
		"self.audio_speaker.set_volume",
		"self.screen.set_brightness",
		"self.watch.get_status",
		"self.watch.set_timezone",
		"self.watch.set_screen",
		"self.watch.set_raise_to_wake",
		"self.watch.start_countdown",
		"self.watch.set_alarm",
		"self.watch.cancel_alerts",
		"self.reboot",
	})
	found := make(map[string]bool)
	for _, tool := range session.AvailableTools() {
		found[tool.Name] = true
	}
	for _, name := range []string{
		"device_get_status", "device_set_volume", "device_set_brightness",
		"watch_get_status", "watch_set_timezone", "watch_set_screen",
		"watch_set_raise_to_wake", "watch_start_countdown", "watch_set_alarm",
		"watch_cancel_alerts", "device_reboot",
	} {
		if !found[name] {
			t.Fatalf("native XiaoZhi tool did not expose %q: %+v", name, found)
		}
	}
	if tool, ready := session.firstTool(
		"device.get_status", "self.get_device_status"); !ready ||
		tool != "self.get_device_status" {
		t.Fatalf("native status alias did not resolve: tool=%q ready=%v", tool, ready)
	}
}

func TestSimplifiedDeviceRequestsUseSmartToolRoute(t *testing.T) {
	for _, transcript := range []string{
		"查询设备电量", "把音量调到百分之八十", "重新启动设备",
		"把時區改成台北", "亮度調到百分之五十", "關閉螢幕",
		"關閉抬腕亮屏", "倒數三分鐘", "設定早上七點鬧鐘", "取消鬧鐘",
	} {
		if !requiresAgentToolTurn(transcript, nil, true) {
			t.Fatalf("device request was not routed to tools: %q", transcript)
		}
	}
}
