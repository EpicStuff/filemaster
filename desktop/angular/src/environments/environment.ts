// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.

// Resolve the daemon's API address for dev builds.
//
// Default: use the current page's host so ng serve routes API calls through
// proxy.json (same-origin, no CORS). To point at a different daemon port
// (e.g. --api-address 127.0.0.1:9999), open the UI with ?api-port=9999 once;
// the port is persisted in localStorage so subsequent loads keep using it.
// To reset to the default, delete 'filemaster-api-port' in devtools storage.
const STORAGE_KEY = 'filemaster-api-port';

function resolveApiHost(): string {
	if (typeof window !== 'undefined') {
		try {
			const fromUrl = new URLSearchParams(window.location.search).get('api-port');
			if (fromUrl && /^\d{1,5}$/.test(fromUrl)) {
				window.localStorage.setItem(STORAGE_KEY, fromUrl);
				return `127.0.0.1:${fromUrl}`;
			}
			const stored = window.localStorage.getItem(STORAGE_KEY);
			if (stored && /^\d{1,5}$/.test(stored)) {
				return `127.0.0.1:${stored}`;
			}
			// Default: use current host so ng serve proxies through proxy.json
			// (same-origin → no CORS, no --devmode needed on the daemon).
			return window.location.host;
		} catch {
			// SSR / sandboxed iframe / private mode -- fall through.
		}
	}
	return '127.0.0.1:818';
}

const apiHost = resolveApiHost();

export const environment = {
	production: false,
	portAPI: `ws://${apiHost}/api/database/v1`,
	httpAPI: `http://${apiHost}/api`,
	supportHub: 'https://support.safing.io'
};

/*
 * For easier debugging in development mode, you can import the following file
 * to ignore zone related error stack frames such as `zone.run`, `zoneDelegate.invokeTask`.
 *
 * This import should be commented out in production mode because it will have a negative impact
 * on performance if an error is thrown.
 */
import 'zone.js/dist/zone-error';  // Included with Angular CLI.
