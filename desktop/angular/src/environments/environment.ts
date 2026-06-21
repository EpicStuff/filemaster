// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.

// Resolve the daemon's API address for dev builds.
//
// Default is 127.0.0.1:818. To point the dashboard at a different
// daemon port (e.g. when you started pm-core with --api-address
// 127.0.0.1:9999), open the UI with ?api-port=9999 once; the port
// is persisted in localStorage so subsequent loads (including the
// /prompt route, which has no query string) keep using it. Clear
// it by visiting ?api-port=818 or deleting the entry in devtools.
const STORAGE_KEY = 'filemaster-api-port';
const DEFAULT_PORT = '818';

function resolveApiHost(): string {
	let port = DEFAULT_PORT;
	if (typeof window !== 'undefined') {
		try {
			const fromUrl = new URLSearchParams(window.location.search).get('api-port');
			if (fromUrl && /^\d{1,5}$/.test(fromUrl)) {
				port = fromUrl;
				window.localStorage.setItem(STORAGE_KEY, fromUrl);
			} else {
				const stored = window.localStorage.getItem(STORAGE_KEY);
				if (stored && /^\d{1,5}$/.test(stored)) {
					port = stored;
				}
			}
		} catch {
			// SSR / sandboxed iframe / private mode -- fall through.
		}
	}
	return `127.0.0.1:${port}`;
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
