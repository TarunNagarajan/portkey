import { z } from 'zod';

export const roomInput = z
  .object({
    title: z.string().trim().min(1).max(100),
    description: z.string().trim().max(500).default(''),
    expiresAt: z.iso.datetime({ offset: true }),
    admissionPolicy: z.enum(['approval', 'pass', 'proof']).optional(),
  })
  .strict();

export const roomTemplateInput = roomInput.extend({
  title: roomInput.shape.title.optional(),
  description: roomInput.shape.description.removeDefault().optional(),
});

export const roomId = z.uuid();
export const joinCode = z.string().regex(/^[A-Za-z0-9_-]{16}$/);
export const memberDecision = z
  .object({
    status: z.enum(['approved', 'denied', 'revoked']),
  })
  .strict();

export type RoomInput = z.infer<typeof roomInput>;
export type RoomStatus = 'draft' | 'open' | 'closed' | 'expired';
export type MembershipStatus = 'pending' | 'approved' | 'denied' | 'revoked';

export const minRadiusM = 50;
export const maxRadiusM = 50000;

export const geoRule = z
  .object({
    lat: z.number().min(-90).max(90),
    lng: z.number().min(-180).max(180),
    radiusM: z.number().int().min(minRadiusM).max(maxRadiusM),
  })
  .strict();

export const geoSource = z.enum(['search', 'device']);

export const geoAreaInput = z
  .object({
    lat: z.number().min(-90).max(90),
    lng: z.number().min(-180).max(180),
    radiusM: z.number().int().min(minRadiusM).max(maxRadiusM),
    label: z.string().trim().min(1).max(120).optional(),
    source: geoSource.optional(),
  })
  .strict();

export const placeQuery = z
  .object({
    q: z.string().trim().min(2).max(120),
  })
  .strict();

export const positionReport = z
  .object({
    lat: z.number().min(-90).max(90),
    lng: z.number().min(-180).max(180),
    accuracyM: z.number().min(0).max(1000),
    timestamp: z.iso.datetime({ offset: true }),
  })
  .strict();

export const joinRequest = z
  .object({
    label: z.string().trim().min(1).max(50),
    lat: z.number().min(-90).max(90).optional(),
    lng: z.number().min(-180).max(180).optional(),
    accuracyM: z.number().min(0).max(1000).optional(),
    timestamp: z.iso.datetime({ offset: true }).optional(),
  })
  .strict();

export type GeoRule = z.infer<typeof geoRule>;
export type GeoSource = z.infer<typeof geoSource>;
export type GeoAreaInput = z.infer<typeof geoAreaInput>;

export interface Room {
  id: string;
  title: string;
  description: string;
  status: RoomStatus;
  expiresAt: string;
  createdAt: string;
  role: 'owner' | 'participant';
  membershipStatus: MembershipStatus | null;
  joinCode: string;
  submissionCleanupEnabled: boolean;
  submissionsPurgedAt: string | null;
  geo: GeoRule | null;
  geoLabel: string | null;
  admissionPolicy: 'approval' | 'pass' | 'proof';
}

export interface PublicRoom {
  id: string;
  title: string;
  description: string;
  status: RoomStatus;
  expiresAt: string;
  membershipStatus: MembershipStatus | null;
  isOwner: boolean;
  organizerKeyFingerprint: string | null;
  organizerPublicKey: string | null;
  submissionCleanupEnabled: boolean;
  submissionsPurgedAt: string | null;
  geo: GeoRule | null;
  geoLabel: string | null;
  needsLocation: boolean;
  admissionPolicy: 'approval' | 'pass' | 'proof';
}

export interface Member {
  id: string;
  label: string;
  status: MembershipStatus;
  requestedAt: string;
  inside: boolean | null;
  distanceM: number | null;
  accuracyM: number | null;
  checkedAt: string | null;
}

export interface PlaceSuggestion {
  label: string;
  lat: number;
  lng: number;
  radiusM: number;
}
