package kittoku.osc.preference

import android.net.Uri
import kittoku.osc.DEFAULT_MRU
import kittoku.osc.DEFAULT_MTU


internal enum class OscPrefKey {
    ROOT_STATE,
    HOME_HOSTNAME,
    HOME_USERNAME,
    HOME_PASSWORD,
    HOME_CONNECTOR,
    HOME_STATUS,
    SSL_PORT,
    SSL_VERSION,
    SSL_DO_VERIFY,
    SSL_DO_ADD_CERT,
    SSL_CERT_DIR,
    SSL_DO_SELECT_SUITES,
    SSL_SUITES,
    PROXY_DO_USE_PROXY,
    PROXY_HOSTNAME,
    PROXY_PORT,
    PROXY_USERNAME,
    PROXY_PASSWORD,
    PPP_MRU,
    PPP_MTU,
    PPP_PAP_ENABLED,
    PPP_MSCHAPv2_ENABLED,
    PPP_AUTH_TIMEOUT,
    PPP_IPv4_ENABLED,
    PPP_DO_REQUEST_STATIC_IPv4_ADDRESS,
    PPP_STATIC_IPv4_ADDRESS,
    PPP_IPv6_ENABLED,
    DNS_DO_REQUEST_ADDRESS,
    DNS_DO_USE_CUSTOM_SERVER,
    DNS_CUSTOM_ADDRESS,
    ROUTE_DO_ADD_DEFAULT_ROUTE,
    ROUTE_DO_ROUTE_PRIVATE_ADDRESSES,
    ROUTE_DO_ADD_CUSTOM_ROUTES,
    ROUTE_CUSTOM_ROUTES,
    ROUTE_DO_ENABLE_APP_BASED_RULE,
    ROUTE_ALLOWED_APPS,
    RECONNECTION_ENABLED,
    RECONNECTION_COUNT,
    RECONNECTION_INTERVAL,
    RECONNECTION_LIFE,
    LOG_DO_SAVE_LOG,
    LOG_DIR,
}


internal val DEFAULT_BOOLEAN_MAP = mapOf(
    OscPrefKey.ROOT_STATE to false,
    OscPrefKey.HOME_CONNECTOR to false,
    OscPrefKey.SSL_DO_VERIFY to true,
    OscPrefKey.SSL_DO_ADD_CERT to false,
    OscPrefKey.SSL_DO_SELECT_SUITES to false,
    OscPrefKey.PROXY_DO_USE_PROXY to false,
    OscPrefKey.PPP_PAP_ENABLED to true,
    OscPrefKey.PPP_MSCHAPv2_ENABLED to true,
    OscPrefKey.PPP_IPv4_ENABLED to true,
    OscPrefKey.PPP_DO_REQUEST_STATIC_IPv4_ADDRESS to false,
    OscPrefKey.PPP_IPv6_ENABLED to false,
    OscPrefKey.DNS_DO_REQUEST_ADDRESS to true,
    OscPrefKey.DNS_DO_USE_CUSTOM_SERVER to false,
    OscPrefKey.ROUTE_DO_ADD_DEFAULT_ROUTE to true,
    OscPrefKey.ROUTE_DO_ROUTE_PRIVATE_ADDRESSES to false,
    OscPrefKey.ROUTE_DO_ADD_CUSTOM_ROUTES to false,
    OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE to false,
    OscPrefKey.RECONNECTION_ENABLED to false,
    OscPrefKey.LOG_DO_SAVE_LOG to false
)

internal val DEFAULT_INT_MAP = mapOf(
    OscPrefKey.SSL_PORT to 443,
    OscPrefKey.PROXY_PORT to 8080,
    OscPrefKey.PPP_MRU to DEFAULT_MRU,
    OscPrefKey.PPP_MTU to DEFAULT_MTU,
    OscPrefKey.PPP_AUTH_TIMEOUT to 3,
    OscPrefKey.RECONNECTION_COUNT to 3,
    OscPrefKey.RECONNECTION_INTERVAL to 10,
    OscPrefKey.RECONNECTION_LIFE to 0
)

private const val EMPTY_TEXT = ""

internal val DEFAULT_STRING_MAP = mapOf(
    OscPrefKey.HOME_HOSTNAME to EMPTY_TEXT,
    OscPrefKey.HOME_USERNAME to EMPTY_TEXT,
    OscPrefKey.HOME_PASSWORD to EMPTY_TEXT,
    OscPrefKey.HOME_STATUS to EMPTY_TEXT,
    OscPrefKey.PROXY_HOSTNAME to EMPTY_TEXT,
    OscPrefKey.PROXY_USERNAME to EMPTY_TEXT,
    OscPrefKey.PROXY_PASSWORD to EMPTY_TEXT,
    OscPrefKey.PPP_STATIC_IPv4_ADDRESS to EMPTY_TEXT,
    OscPrefKey.DNS_CUSTOM_ADDRESS to EMPTY_TEXT,
    OscPrefKey.ROUTE_CUSTOM_ROUTES to EMPTY_TEXT,
    OscPrefKey.SSL_VERSION to "DEFAULT",
)

private val EMPTY_SET = setOf<String>()

internal val DEFAULT_SET_MAP = mapOf(
    OscPrefKey.SSL_SUITES to EMPTY_SET,
    OscPrefKey.ROUTE_ALLOWED_APPS to EMPTY_SET,
)

internal val DEFAULT_URI_MAP = mapOf<OscPrefKey, Uri?>(
    OscPrefKey.SSL_CERT_DIR to null,
    OscPrefKey.LOG_DIR to null,
)


internal const val TEMP_KEY_HEADER = "_"
internal const val PROFILE_KEY_HEADER = "PROFILE."
