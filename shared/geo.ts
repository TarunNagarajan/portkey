import { maxRadiusM, minRadiusM } from './rooms.js';

export interface GeoPoint {
  lat: number;
  lng: number;
}

export interface GeoRule extends GeoPoint {
  radiusM: number;
}

export interface GeoFix extends GeoPoint {
  accuracyM: number;
}

const EARTH_RADIUS_M = 6371000;

function toRadians(degrees: number) {
  return (degrees * Math.PI) / 180;
}

export function haversineMeters(a: GeoPoint, b: GeoPoint) {
  const dLat = toRadians(b.lat - a.lat);
  const dLng = toRadians(b.lng - a.lng);
  const lat1 = toRadians(a.lat);
  const lat2 = toRadians(b.lat);
  const h =
    Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return 2 * EARTH_RADIUS_M * Math.asin(Math.min(1, Math.sqrt(h)));
}

export function isInside(fix: GeoPoint, rule: GeoRule) {
  return haversineMeters(fix, rule) <= rule.radiusM;
}

export function deriveRadius(accuracyM: number) {
  if (!Number.isFinite(accuracyM) || accuracyM <= 0) return 150;
  return Math.min(150, Math.max(50, Math.round(accuracyM * 2)));
}

const METERS_PER_DEGREE_LAT = 111_320;

// Nominatim returns a bounding box as [south, north, west, east] in degrees.
// A circle covering the box has a radius of half the longer side.
export function suggestRadiusFromBbox(bbox: number[]) {
  const [south, north, west, east] = bbox;
  if (![south, north, west, east].every((value) => Number.isFinite(value))) return 150;
  const centerLat = (south + north) / 2;
  const northSouthM = Math.abs(north - south) * METERS_PER_DEGREE_LAT;
  const eastWestM =
    Math.abs(east - west) * METERS_PER_DEGREE_LAT * Math.cos(toRadians(centerLat));
  const radius = Math.max(northSouthM, eastWestM) / 2;
  return Math.min(maxRadiusM, Math.max(minRadiusM, Math.round(radius)));
}

export function median(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

export function medianFix(fixes: GeoFix[]): GeoFix {
  return {
    lat: median(fixes.map((fix) => fix.lat)),
    lng: median(fixes.map((fix) => fix.lng)),
    accuracyM: median(fixes.map((fix) => fix.accuracyM)),
  };
}

export function locationAccuracyMessage(accuracyM: number, requiredM: number) {
  const accuracy = accuracyM >= 1000 ? `${(accuracyM / 1000).toFixed(1)} km` : `${Math.round(accuracyM)} m`;
  return `Your location is only accurate to about ${accuracy}. This room needs ${requiredM} m or better. Enable precise location for your browser, then retry near a window or outdoors.`;
}
