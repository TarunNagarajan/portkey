import type { PlaceSuggestion } from '../shared/rooms.js';
import { suggestRadiusFromBbox } from '../shared/geo.js';

export interface Geocoder {
  search(query: string): Promise<PlaceSuggestion[]>;
  reverse(lat: number, lng: number): Promise<string | null>;
}

const DEFAULT_BASE_URL = 'https://nominatim.openstreetmap.org';
const USER_AGENT = 'portkey-geofence/0.1';
const TIMEOUT_MS = 3000;

interface NominatimResult {
  lat?: string;
  lon?: string;
  display_name?: string;
  boundingbox?: string[];
}

async function getJson(url: string): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': USER_AGENT, 'Accept-Language': 'en' },
      signal: controller.signal,
    });
    if (!response.ok) return null;
    return (await response.json()) as unknown;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const disabled: Geocoder = {
  search: async () => [],
  reverse: async () => null,
};

export function createGeocoder(
  enabled: boolean,
  baseUrl: string = DEFAULT_BASE_URL,
): Geocoder {
  if (!enabled) return disabled;
  return {
    async search(query) {
      const data = await getJson(
        `${baseUrl}/search?format=jsonv2&limit=5&q=${encodeURIComponent(query)}`,
      );
      if (!Array.isArray(data)) return [];
      const suggestions: PlaceSuggestion[] = [];
      for (const item of data as NominatimResult[]) {
        const lat = Number(item.lat);
        const lng = Number(item.lon);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue;
        const bbox = (item.boundingbox ?? []).map(Number);
        suggestions.push({
          label: (item.display_name ?? 'Selected place').slice(0, 120),
          lat,
          lng,
          radiusM: bbox.length === 4 ? suggestRadiusFromBbox(bbox) : 200,
        });
      }
      return suggestions;
    },
    async reverse(lat, lng) {
      const data = (await getJson(
        `${baseUrl}/reverse?format=jsonv2&zoom=14&lat=${lat}&lon=${lng}`,
      )) as NominatimResult | null;
      const name = data?.display_name;
      if (!name) return null;
      return name.split(',').slice(0, 3).join(',').trim().slice(0, 120) || null;
    },
  };
}
