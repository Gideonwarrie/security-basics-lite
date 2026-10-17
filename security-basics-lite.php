<?php
/**
 * Plugin Name:       Security Basics Lite
 * Description:       Lightweight WordPress hardening: hides the version number (including in script links), blocks XML-RPC logins, adds basic security headers and stops user-name enumeration.
 * Version:           1.1.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Gideon Warrie
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       security-basics-lite
 */

// Stop anyone from running this file directly (outside WordPress).
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * 1. HIDE THE WORDPRESS VERSION
 * Attackers look for known bugs in specific versions, so don't advertise it.
 */
remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );

/*
 * 2. BLOCK XML-RPC LOGINS
 * xmlrpc.php is a common target for brute-force login attempts.
 * Note: this can break apps that rely on XML-RPC (e.g. old mobile apps, Jetpack).
 */
add_filter( 'xmlrpc_enabled', '__return_false' );

function sbl_remove_pingback_methods( $methods ) {
	unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
	return $methods;
}
add_filter( 'xmlrpc_methods', 'sbl_remove_pingback_methods' );

function sbl_remove_pingback_header( $headers ) {
	unset( $headers['X-Pingback'] );
	return $headers;
}
add_filter( 'wp_headers', 'sbl_remove_pingback_header' );

/*
 * 3. SECURITY HEADERS
 * Instructions sent to the browser that reduce common attacks.
 */
function sbl_send_security_headers() {
	if ( headers_sent() ) {
		return;
	}
	header( 'X-Content-Type-Options: nosniff' );                       // Stop browsers guessing file types.
	header( 'X-Frame-Options: SAMEORIGIN' );                           // Stop other sites framing yours (clickjacking).
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );      // Limit what URL info leaks to other sites.
	header( 'Permissions-Policy: geolocation=(), camera=(), microphone=()' ); // Switch off features you don't use.
}
add_action( 'send_headers', 'sbl_send_security_headers' );

/*
 * 4. STOP USER-NAME ENUMERATION
 * Attackers find real usernames first, then guess passwords.
 * (a) Block /?author=1 scans for logged-out visitors.
 */
function sbl_block_author_scan() {
	if ( is_admin() || is_user_logged_in() ) {
		return;
	}
	if ( isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		wp_safe_redirect( home_url( '/' ) );
		exit;
	}
}
add_action( 'template_redirect', 'sbl_block_author_scan' );

// (b) Hide the REST API user list from logged-out visitors.
function sbl_hide_rest_users( $endpoints ) {
	if ( ! is_user_logged_in() ) {
		unset( $endpoints['/wp/v2/users'] );
		unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
	}
	return $endpoints;
}
add_filter( 'rest_endpoints', 'sbl_hide_rest_users' );

/*
 * 5. HIDE THE VERSION IN SCRIPT AND STYLE LINKS
 * Many links end in ?ver=<number>. When that number is the WordPress version,
 * it reveals it. We only remove it when it matches the core version, so theme
 * and plugin files keep their own version numbers (which help browsers fetch
 * fresh copies after an update).
 */
function sbl_strip_core_version( $src ) {
	if ( ! is_string( $src ) ) {
		return $src;
	}
	$query = wp_parse_url( $src, PHP_URL_QUERY );
	if ( ! $query ) {
		return $src;
	}
	parse_str( $query, $args );
	if ( isset( $args['ver'] ) && get_bloginfo( 'version' ) === $args['ver'] ) {
		$src = remove_query_arg( 'ver', $src );
	}
	return $src;
}
add_filter( 'style_loader_src', 'sbl_strip_core_version', 15 );
add_filter( 'script_loader_src', 'sbl_strip_core_version', 15 );

/*
 * 6. REMOVE THE EMOJI LOADER
 * WordPress prints its own emoji script and builds that link in a way the
 * filter above cannot change, so it still leaks the version. Modern browsers
 * show emoji natively, so removing it is safe and saves a request.
 * (Hook names differ slightly between WordPress versions, so both are listed.)
 */
remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
remove_action( 'wp_print_styles', 'print_emoji_styles' );
remove_action( 'wp_enqueue_scripts', 'wp_enqueue_emoji_styles' );
remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
remove_action( 'admin_print_styles', 'print_emoji_styles' );
