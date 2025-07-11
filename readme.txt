=== Login Sentinel ===
Contributors: amalp
Tags: login security, ip monitoring, suspicious login, admin alert
Requires at least: 5.0
Tested up to: 6.8
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Login Sentinel is a lightweight watchdog plugin that detects suspicious logins based on IP/geolocation changes and alerts the admin.

== Description ==

Login Sentinel helps protect your WordPress site by tracking user logins:
- Logs login events with IP, time, and browser
- Detects suspicious logins from different IPs
- Alerts admin via email
- Shows suspicious login history
- Includes dashboard widget and settings panel

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/login-sentinel` directory, or install via WordPress Plugins screen.
2. Activate the plugin.
3. Go to `Settings > Login Sentinel` to enable alerts or logging.

== Frequently Asked Questions ==

= Does it block users? =
No. This is a detection + alert plugin, not a firewall or brute force blocker.

= Can I see suspicious login history? =
Yes, in your dashboard widget or the logs directory.

== Screenshots ==
1. Dashboard widget showing login summary
2. Settings panel to enable/disable alerts

== Changelog ==
= 1.0.0 =
* Initial release – login monitoring, IP change detection, email alerting

== Upgrade Notice ==
First release – please report bugs or feature requests on GitHub.
