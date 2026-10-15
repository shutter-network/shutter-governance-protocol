/** The crypto SDK the downloadable verification scripts install. Pinned to the version
 *  the apps use: the scripts call its API directly, and an unpinned install would pick
 *  up whatever a future release changes. */
export const SDK_PACKAGE = "@shutter-network/urban-verified-crypto";
export const SDK_VERSION = "0.3.0";
