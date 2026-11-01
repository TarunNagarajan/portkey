import { maxEntryAccuracyM } from '../shared/rooms.js';
import { locationAccuracyMessage } from '../shared/geo.js';

export interface GeoFix {
  lat: number;
  lng: number;
  accuracyM: number;
  timestamp: string;
}

interface LocationOptions {
  maxAccuracyM?: number;
  timeoutMs?: number;
  geolocation?: Pick<Geolocation, 'watchPosition' | 'clearWatch'>;
}

// Phones can initially report a coarse network fix while GPS warms up. Keep
// listening for an accurate, fresh reading, preserving its coordinates/time as
// one measurement instead of combining unrelated samples.
export function requestFix(options: LocationOptions = {}): Promise<GeoFix> {
  const maxAccuracyM = options.maxAccuracyM ?? maxEntryAccuracyM;
  const timeoutMs = options.timeoutMs ?? 20_000;
  return new Promise((resolve, reject) => {
    const geolocation = options.geolocation ?? (typeof navigator === 'undefined' ? undefined : navigator.geolocation);
    if (!geolocation) {
      reject(new Error('Location is not supported on this device or browser.'));
      return;
    }
    let watchId: number | undefined;
    let settled = false;
    let best: GeoFix | undefined;
    let lastError = 'Location timed out. Enable precise location for your browser and try again near a window or outdoors.';
    const finish = (fix?: GeoFix, error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (watchId !== undefined) geolocation.clearWatch(watchId);
      if (fix) resolve(fix);
      else reject(error ?? new Error(lastError));
    };
    const timer = setTimeout(() => finish(undefined, best
      ? new Error(locationAccuracyMessage(best.accuracyM, maxAccuracyM))
      : new Error(lastError)), timeoutMs);
    try {
      watchId = geolocation.watchPosition(position => {
        if (settled) return;
        const { latitude: lat, longitude: lng, accuracy: accuracyM } = position.coords;
        const age = Date.now() - position.timestamp;
        if (![lat, lng, accuracyM, age].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lng) > 180 || accuracyM < 0 || age < -30_000 || age > 60_000) return;
        const fix = { lat, lng, accuracyM, timestamp: new Date(position.timestamp).toISOString() };
        if (!best || accuracyM < best.accuracyM) best = fix;
        if (accuracyM <= maxAccuracyM) finish(fix);
      }, error => {
        if (error.code === 1) {
          finish(undefined, new Error('Location permission was denied. Allow location access for your browser and try again.'));
        } else if (error.code === 2) {
          lastError = 'Location is unavailable. Enable precise location for your browser and try again near a window or outdoors.';
        }
        // Timeout/unavailability can be transient; keep watching until our
        // overall deadline, unless permission was explicitly denied.
      }, { enableHighAccuracy: true, maximumAge: 0, timeout: timeoutMs });
      if (settled && watchId !== undefined) geolocation.clearWatch(watchId);
    } catch (error) {
      finish(undefined, error instanceof Error ? error : new Error(lastError));
    }
  });
}
