import assert from 'node:assert/strict';
import { test } from 'node:test';
import { requestFix } from '../client/location.js';

function position(lat: number, accuracy: number, timestamp = Date.now()): GeolocationPosition {
  return { timestamp, coords: { latitude: lat, longitude: 79.5941, accuracy,
    altitude: null, altitudeAccuracy: null, heading: null, speed: null, toJSON: () => ({}) }, toJSON: () => ({}) };
}
function fakeLocation(readings: GeolocationPosition[], errorCode?: number) {
  const cleared: number[] = [];
  let callback: PositionCallback | undefined;
  const geolocation = {
    watchPosition(success: PositionCallback, error?: PositionErrorCallback | null, options?: PositionOptions) {
      assert.equal(options?.enableHighAccuracy, true); assert.equal(options?.maximumAge, 0);
      callback = success;
      queueMicrotask(() => {
        for (const reading of readings) success(reading);
        if (errorCode) error?.({ code: errorCode, message: '', PERMISSION_DENIED: 1, POSITION_UNAVAILABLE: 2, TIMEOUT: 3 });
      });
      return 7;
    },
    clearWatch(id: number) { cleared.push(id); },
  };
  return { geolocation, cleared, late: (reading: GeolocationPosition) => callback?.(reading) };
}

test('a coarse initial phone reading waits for an accurate fix and preserves that measurement', async () => {
  const precise = position(17.9689, 12);
  const fake = fakeLocation([position(18, 2500), precise]);
  const result = await requestFix({ geolocation: fake.geolocation, timeoutMs: 100 });
  assert.deepEqual(result, { lat: precise.coords.latitude, lng: precise.coords.longitude, accuracyM: 12, timestamp: new Date(precise.timestamp).toISOString() });
  assert.deepEqual(fake.cleared, [7]);
  fake.late(position(19, 1));
  assert.equal(result.lat, precise.coords.latitude);
});

test('coarse-only readings give precise-location guidance and stop the GPS watch', async () => {
  const fake = fakeLocation([position(18, 5000), position(17.9689, 2500)]);
  await assert.rejects(requestFix({ geolocation: fake.geolocation, timeoutMs: 10 }), /2\.5 km.*75 m.*Enable precise location/);
  assert.deepEqual(fake.cleared, [7]);
});

test('stale readings cannot win over a fresh fix and permission denial ends immediately', async () => {
  const fake = fakeLocation([position(18, 1, Date.now() - 120_000), position(17.9689, 50)]);
  assert.equal((await requestFix({ geolocation: fake.geolocation })).lat, 17.9689);
  const denied = fakeLocation([], 1);
  await assert.rejects(requestFix({ geolocation: denied.geolocation }), /permission was denied/);
  assert.deepEqual(denied.cleared, [7]);
});
