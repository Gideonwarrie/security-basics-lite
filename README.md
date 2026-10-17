# Security Basics Lite

A small WordPress plugin that applies a few common hardening steps. Written in PHP using WordPress hooks (actions and filters).

## Features

- **Hides the WordPress version** from the page source, and from script and style links (`?ver=`) when the number matches the core version.
- **Removes the WordPress emoji loader**, which also exposes the version.
- **Blocks XML-RPC logins** and removes the pingback methods and header.
- **Adds security headers**: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.
- **Reduces user-name enumeration**: blocks `/?author=N` scans and hides the REST API user list from logged-out visitors.

## Install

1. Download `security-basics-lite.zip`.
2. In WordPress go to **Plugins > Add New > Upload Plugin**, choose the zip, then **Activate**.

## How to check it works

- **Version hidden:** view the page source and search for `generator`. No WordPress version should appear.
- **Author scan blocked:** while logged out, open `yoursite/?author=1`. You should land on the home page.
- **REST users hidden:** while logged out, open `yoursite/wp-json/wp/v2/users`. You should get a "no route" error.
- **Headers:** scan your site at securityheaders.com.

## Limitations

- Disabling XML-RPC can break apps that depend on it.
- Author archive pages at `/author/username/` can still reveal usernames.
- If a host or caching plugin serves saved copies of pages, WordPress's PHP never runs for them, so the headers will not appear on those pages. Some hosts also set their own `Referrer-Policy`, which can take precedence over this plugin's value.
- This is a learning project, not a replacement for a full security plugin.

## License

GPL-2.0-or-later
