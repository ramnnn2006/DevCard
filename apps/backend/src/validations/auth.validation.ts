import { z } from 'zod';

export const oAuthStartSchema = z.object({
  state: z.string().optional().default(''),
  mobile_redirect_uri: z
    .string()
    .optional()
    .default('')
    .refine(
      (val) => !val || val.startsWith('devcard://'),
      { message: 'Invalid mobile redirect URI' }
    ),
});

export type OAuthStartQuery = z.infer<typeof oAuthStartSchema>;

export const oauthCallbackSchema = z.object({
  code: z.string().min(1, 'Authorization code is required'),
  state: z.string().min(1, 'State parameter is required'),
});