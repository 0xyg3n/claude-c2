# MCP Remote Agent - Android/Termux Operations

This guide covers Android-specific capabilities when using the Termux agent.

## Table of Contents
- [Quick Start](#quick-start)
- [YouTube Control](#youtube-control)
- [Media Control](#media-control)
- [App Launching](#app-launching)
- [Termux API Integration](#termux-api-integration)
- [File Operations](#file-operations)
- [Examples](#examples)

---

## Quick Start

### Deploy Agent on Termux
```bash
curl -s https://YOUR_DOMAIN/agent/termux | bash
```

Or with custom ID:
```bash
MCP_ID='MY-PHONE' bash -c "$(curl -s https://YOUR_DOMAIN/agent/termux)"
```

### Requirements
- Termux app (F-Droid or Google Play)
- Python 3.7+ with websockets (`pip install websockets`)
- Optional: Termux:API for extended features

---

## YouTube Control

### The Working Method: `xdg-open`

The most reliable way to open YouTube videos on Android/Termux:

```bash
xdg-open "https://www.youtube.com/watch?v=VIDEO_ID"
```

### Why xdg-open Works
- Universal URL/file opener in Linux/Android
- Automatically launches the YouTube app
- Works on both Google Play and F-Droid Termux
- No special permissions required
- Consistent behavior across Android versions

### Examples

**Via Claude.ai MCP:**
```
"Play the Rickroll video on my phone"
"Open YouTube video dQw4w9WgXcQ"
"Play https://www.youtube.com/watch?v=9bZkp7q19f0"
```

**Shell commands:**
```bash
# Rickroll
shell(cmd="xdg-open 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'")

# Gangnam Style
shell(cmd="xdg-open 'https://www.youtube.com/watch?v=9bZkp7q19f0'")

# Despacito
shell(cmd="xdg-open 'https://www.youtube.com/watch?v=kJQP7kiw5Fk'")

# Any video URL
shell(cmd="xdg-open 'https://youtu.be/VIDEO_ID'")
```

### Alternative Methods (Less Reliable)

**Using am start (Android Activity Manager):**
```bash
# May not work on all Termux versions
am start -a android.intent.action.VIEW -d "https://www.youtube.com/watch?v=VIDEO_ID"
```

**Using termux-open-url:**
```bash
# Requires Termux:API
termux-open-url "https://www.youtube.com/watch?v=VIDEO_ID"
```

---

## Media Control

### Open URLs in Default Browser
```bash
xdg-open "https://example.com"
```

### Open Maps Location
```bash
xdg-open "geo:37.7749,-122.4194"
xdg-open "geo:0,0?q=Times+Square"
```

### Make Phone Call (requires Termux:API)
```bash
termux-telephony-call "+15551234567"
```

### Send SMS (requires Termux:API)
```bash
termux-sms-send -n "+15551234567" "Hello from MCP!"
```

---

## App Launching

### Using xdg-open with URLs
```bash
# Browser
xdg-open "https://google.com"

# Email
xdg-open "mailto:user@example.com?subject=Hello"

# Phone
xdg-open "tel:+15551234567"

# Maps
xdg-open "geo:40.7128,-74.0060"
```

### Using am start
```bash
# Open specific app
am start -n com.package.name/.MainActivity

# Open URL in browser
am start -a android.intent.action.VIEW -d "https://example.com"

# Open camera
am start -a android.media.action.IMAGE_CAPTURE
```

---

## Termux API Integration

Install Termux:API from F-Droid for extended capabilities:

### Device Info
```bash
termux-battery-status      # Battery info
termux-wifi-connectioninfo # WiFi details
termux-location            # GPS location
```

### Notifications
```bash
termux-notification --title "Alert" --content "Message from C2"
termux-toast "Quick message"
```

### Media
```bash
termux-camera-photo -c 0 photo.jpg    # Take photo
termux-audio-info                      # Audio info
termux-volume                          # Volume control
```

### Sensors
```bash
termux-sensor -l                       # List sensors
termux-sensor -s accelerometer -n 5    # Read sensor
```

### Clipboard
```bash
termux-clipboard-get                   # Get clipboard
termux-clipboard-set "text"            # Set clipboard
```

---

## File Operations

### Common Paths on Android/Termux
```bash
# Termux home
/data/data/com.termux/files/home

# Internal storage (requires permission)
/storage/emulated/0

# Downloads
/storage/emulated/0/Download

# DCIM (photos)
/storage/emulated/0/DCIM
```

### Access Storage
First, grant storage permission:
```bash
termux-setup-storage
```

Then access files:
```bash
ls /storage/emulated/0/Download
cat /storage/emulated/0/Download/file.txt
```

---

## Examples

### Play Music Playlist
```bash
# Open YouTube playlist
xdg-open "https://www.youtube.com/playlist?list=PLAYLIST_ID"
```

### Wake Up Alarm
```bash
# Set notification
termux-notification --title "Wake Up!" --content "Time to get up" --sound
```

### Location Check
```bash
# Get current location
termux-location -p gps
```

### Screenshot Alternative
```bash
# Take photo with front camera
termux-camera-photo -c 1 /storage/emulated/0/DCIM/screenshot.jpg
```

### Full Recon
```bash
# Gather device info
echo "=== Battery ===" && termux-battery-status
echo "=== WiFi ===" && termux-wifi-connectioninfo
echo "=== Location ===" && termux-location
```

---

## Troubleshooting

### xdg-open Not Working
```bash
# Install xdg-utils if missing
pkg install xdg-utils
```

### Storage Access Denied
```bash
# Run storage setup
termux-setup-storage
# Then restart Termux
```

### Termux API Not Found
```bash
# Install Termux:API app from F-Droid
# Then install termux-api package
pkg install termux-api
```

### Commands Timeout
Some commands (location, camera) take time. Use longer timeouts:
```bash
shell(cmd="termux-location -p gps", timeout=60000)
```

---

## Security Notes

- YouTube/URL opening works without root
- Storage access requires user permission grant
- Termux:API requires the companion app
- Some features need Termux to be in foreground
- Battery optimization may affect background execution

---

## Tested Configurations

| Device | Android | Termux | Status |
|--------|---------|--------|--------|
| Various | 12 | Google Play | ✅ Working |
| Various | 11-13 | F-Droid | ✅ Working |

---

## Support

For issues specific to Android/Termux, check:
- [Termux Wiki](https://wiki.termux.com/)
- [Termux:API Docs](https://wiki.termux.com/wiki/Termux:API)
