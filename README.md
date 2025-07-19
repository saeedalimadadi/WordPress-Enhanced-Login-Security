# WordPress Enhanced Login Security

This code snippet provides basic enhancements to your WordPress login security, focusing on two key areas:

1.  **Login Attempt Limiting:** Limits the number of failed login attempts for a user before temporarily locking them out. This helps protect against brute-force attacks. After 3 failed attempts, a user will be temporarily blocked for 5 minutes.
2.  **Generic Login Errors:** Hides specific error messages on the login page (e.g., "Invalid username" or "Incorrect password"). Instead of revealing whether the username/email exists or if only the password was wrong, it presents a generic error. This makes it harder for attackers to enumerate valid usernames.

## Why use this code?

* **Deter Brute-Force Attacks:** By limiting attempts and temporarily locking out users, you make it significantly harder for automated scripts to guess passwords.
* **Prevent Username Enumeration:** Generic error messages prevent attackers from knowing which usernames are valid on your site, adding a layer of security.
* **Improved Security Posture:** Contributes to a more robust overall security setup for your WordPress installation.

## Features

* Limits failed login attempts to 3.
* Implements a 5-minute temporary lockout after 3 failed attempts per user.
* Resets attempt count upon successful login.
* Replaces specific login error messages with a generic `null` message, effectively hiding the error details.

## Installation

There are two primary methods to implement this code:

### Method 1: As a Standalone Plugin (Recommended)

Creating a small, dedicated plugin is the most robust way to add this functionality. It ensures your modification remains active regardless of theme changes.

1.  Create a new folder named `wp-login-guard` inside your WordPress site's `wp-content/plugins/` directory.
2.  Inside this new folder, create a file named `wp-login-guard.php`.
3.  Copy and paste the following code into `wp-login-guard.php`:

    ```php
    <?php
    /**
     * Plugin Name: WordPress Enhanced Login Security
     * Description: Implements login attempt limiting and removes specific login error messages for enhanced security.
     * Version: 1.0
     * Author: Your Name (Optional)
     * License: GPL-2.0-or-later
     * Text Domain: wp-login-guard
     */

    if ( ! defined( 'ABSPATH' ) ) {
        exit; // Exit if accessed directly.
    }

    /**
     * Limits the number of failed login attempts for a user.
     *
     * @param WP_User|WP_Error $user     WP_User object or WP_Error on failure.
     * @param string           $username The username entered in the login form.
     * @param string           $password The password entered in the login form.
     * @return WP_User|WP_Error
     */
    function limit_login_attempts($user, $username, $password) {
        // Check if the user is already temporarily locked out (for this specific username)
        if (get_transient('limit_login_' . $username)) {
            return new WP_Error('too_many_attempts', __('Too many login attempts. Please try again later.', 'wp-login-guard'));
        }

        // Only proceed if it's a failed login attempt for an *existing* user.
        // If $user is already a WP_Error, it means authentication failed.
        // Also ensure it's not a generic username that doesn't exist.
        if ( is_wp_error( $user ) && $user->get_error_code() == 'incorrect_password' || $user->get_error_code() == 'invalid_username' || $user->get_error_code() == 'invalid_email' ) {

            // Try to get the user by login or email for accurate meta data tracking
            $user_obj = get_user_by( 'login', $username );
            if ( ! $user_obj ) {
                $user_obj = get_user_by( 'email', $username );
            }

            if ( $user_obj && $user_obj->exists() ) {
                $attempts = (int) get_user_meta($user_obj->ID, 'login_attempts', true);
                $attempts++;

                if ($attempts >= 3) { // 3 failed attempts
                    set_transient('limit_login_' . $username, true, 60 * 5); // Lock out for 5 minutes
                    update_user_meta($user_obj->ID, 'login_attempts', 0); // Reset attempts after lockout
                    return new WP_Error('too_many_attempts', __('Too many login attempts. Please try again later.', 'wp-login-guard'));
                }

                update_user_meta($user_obj->ID, 'login_attempts', $attempts);
            }
        }

        // If authentication was successful, ensure login attempts are reset.
        if ( ! is_wp_error( $user ) && $user->ID ) {
             delete_user_meta($user->ID, 'login_attempts');
        }

        return $user;
    }
    add_filter('authenticate', 'limit_login_attempts', 30, 3);

    /**
     * Resets login attempts count on successful login.
     *
     * @param string  $user_login The user's username.
     * @param WP_User $user       The WP_User object.
     */
    function reset_login_attempts_on_success($user_login, $user) {
        delete_user_meta($user->ID, 'login_attempts');
    }
    add_action('wp_login', 'reset_login_attempts_on_success', 10, 2);

    /**
     * Removes specific error messages from the login page.
     *
     * @param string $error The error message.
     * @return null|string Returns null to hide the error, or the error string.
     */
    function remove_login_errors() {
        return null;
    }
    add_filter('login_errors', 'remove_login_errors');
    ```

4.  Go to your WordPress admin dashboard, navigate to **"Plugins"**, and **activate** the "WordPress Enhanced Login Security" plugin.

### Method 2: Adding to your Theme's functions.php File

You can add this code directly to your active theme's `functions.php` file. **Before doing so, it's highly recommended to back up your `functions.php` file.**

1.  Navigate to `wp-content/themes/YourThemeName/` (replace `YourThemeName` with the actual name of your active theme).
2.  Open the `functions.php` file.
3.  Add the following code to the end of the file (before the closing `?>` tag, if one exists):

    ```php
    /**
     * Limits the number of failed login attempts for a user.
     *
     * @param WP_User|WP_Error $user     WP_User object or WP_Error on failure.
     * @param string           $username The username entered in the login form.
     * @param string           $password The password entered in the login form.
     * @return WP_User|WP_Error
     */
    function limit_login_attempts($user, $username, $password) {
        // Check if the user is already temporarily locked out (for this specific username)
        if (get_transient('limit_login_' . $username)) {
            return new WP_Error('too_many_attempts', 'Too many login attempts. Please try again later.');
        }

        // Only proceed if it's a failed login attempt for an *existing* user.
        // If $user is already a WP_Error, it means authentication failed.
        // Also ensure it's not a generic username that doesn't does not exist.
        if ( is_wp_error( $user ) && ( $user->get_error_code() == 'incorrect_password' || $user->get_error_code() == 'invalid_username' || $user->get_error_code() == 'invalid_email' ) ) {

            // Try to get the user by login or email for accurate meta data tracking
            $user_obj = get_user_by( 'login', $username );
            if ( ! $user_obj ) {
                $user_obj = get_user_by( 'email', $username );
            }

            if ( $user_obj && $user_obj->exists() ) {
                $attempts = (int) get_user_meta($user_obj->ID, 'login_attempts', true);
                $attempts++;

                if ($attempts >= 3) { // 3 failed attempts
                    set_transient('limit_login_' . $username, true, 60 * 5); // Lock out for 5 minutes
                    update_user_meta($user_obj->ID, 'login_attempts', 0); // Reset attempts after lockout
                    return new WP_Error('too_many_attempts', 'Too many login attempts. Please try again later.');
                }

                update_user_meta($user_obj->ID, 'login_attempts', $attempts);
            }
        }

        // If authentication was successful, ensure login attempts are reset.
        if ( ! is_wp_error( $user ) && $user->ID ) {
             delete_user_meta($user->ID, 'login_attempts');
        }

        return $user;
    }
    add_filter('authenticate', 'limit_login_attempts', 30, 3);

    /**
     * Resets login attempts count on successful login.
     *
     * @param string  $user_login The user's username.
     * @param WP_User $user       The WP_User object.
     */
    function reset_login_attempts_on_success($user_login, $user) {
        delete_user_meta($user->ID, 'login_attempts');
    }
    add_action('wp_login', 'reset_login_attempts_on_success', 10, 2);

    // Removes specific error messages from the login page.
    function remove_login_errors() {
        return null;
    }
    add_filter('login_errors', 'remove_login_errors');
    ```

## Important Considerations

* **User Experience:** Inform your users about the login attempt limit to prevent confusion if they get locked out. The error message is generic, so you might consider adding an FAQ or information page.
* **Administrator Access:** Ensure you, as an administrator, have alternative ways to access your site if you accidentally get locked out (e.g., via FTP to disable the plugin/code, or a specific backdoor if you've implemented one for emergencies).
* **Complementary Security:** This code provides basic brute-force protection. For comprehensive security, consider using a dedicated security plugin that offers more features like IP blocking, reCAPTCHA, and security logs.

## Contributing

Contributions are welcome! If you have suggestions or improvements for this code, feel free to open a "Pull Request" or report an "Issue."

## License

This project is licensed under the GPL-2.0-or-later License.
# افزایش امنیت ورود به وردپرس

این قطعه کد بهبودهای اساسی را در امنیت ورود به وردپرس شما فراهم می‌کند و بر دو حوزه کلیدی تمرکز دارد:

1.  **محدود کردن تلاش‌های ورود:** تعداد تلاش‌های ورود ناموفق برای یک کاربر را قبل از قفل شدن موقت آن‌ها محدود می‌کند. این به محافظت در برابر حملات brute-force کمک می‌کند. پس از ۳ تلاش ناموفق، یک کاربر به مدت ۵ دقیقه موقتاً مسدود می‌شود.
2.  **خطاهای ورود عمومی:** پیام‌های خطای خاص را در صفحه ورود پنهان می‌کند (مانند "نام کاربری نامعتبر" یا "گذرواژه اشتباه است"). به جای فاش کردن اینکه آیا نام کاربری/ایمیل وجود دارد یا فقط رمز عبور اشتباه بوده است، یک خطای عمومی نمایش می‌دهد. این امر شناسایی نام‌های کاربری معتبر را برای مهاجمان دشوارتر می‌کند.

## چرا از این کد استفاده کنیم؟

* **جلوگیری از حملات Brute-Force:** با محدود کردن تلاش‌ها و قفل کردن موقت کاربران، تشخیص رمز عبور را برای اسکریپت‌های خودکار به طور قابل توجهی دشوارتر می‌کنید.
* **جلوگیری از شناسایی نام کاربری:** پیام‌های خطای عمومی از اطلاع مهاجمان از نام‌های کاربری معتبر در سایت شما جلوگیری می‌کند و یک لایه امنیتی اضافه می‌کند.
* **وضعیت امنیتی بهبود یافته:** به یک تنظیمات امنیتی کلی قوی‌تر برای نصب وردپرس شما کمک می‌کند.

## قابلیت‌ها

* محدود کردن تلاش‌های ورود ناموفق به ۳ بار.
* اجرای یک قفل موقت ۵ دقیقه‌ای پس از ۳ تلاش ناموفق برای هر کاربر.
* بازنشانی شمارنده تلاش‌ها پس از ورود موفق.
* جایگزینی پیام‌های خطای ورود خاص با یک پیام `null` عمومی، که به طور موثر جزئیات خطا را پنهان می‌کند.

## نصب

برای پیاده‌سازی این کد، دو روش اصلی وجود دارد:

### روش ۱: به عنوان یک افزونه مستقل (توصیه شده)

ایجاد یک افزونه کوچک و اختصاصی، قوی‌ترین راه برای افزودن این قابلیت است. این تضمین می‌کند که کد شما صرف‌نظر از تغییر قالب، فعال باقی بماند.

1.  یک پوشه جدید با نام `wp-login-guard` در مسیر `wp-content/plugins/` سایت وردپرسی خود ایجاد کنید.
2.  در داخل این پوشه جدید، یک فایل با نام `wp-login-guard.php` ایجاد کنید.
3.  کد زیر را در `wp-login-guard.php` کپی و جایگذاری کنید:

    ```php
    <?php
    /**
     * Plugin Name: WordPress Enhanced Login Security
     * Description: Implements login attempt limiting and removes specific login error messages for enhanced security.
     * Version: 1.0
     * Author: Your Name (Optional)
     * License: GPL-2.0-or-later
     * Text Domain: wp-login-guard
     */

    if ( ! defined( 'ABSPATH' ) ) {
        exit; // Exit if accessed directly.
    }

    /**
     * Limits the number of failed login attempts for a user.
     *
     * @param WP_User|WP_Error $user     WP_User object or WP_Error on failure.
     * @param string           $username The username entered in the login form.
     * @param string           $password The password entered in the login form.
     * @return WP_User|WP_Error
     */
    function limit_login_attempts($user, $username, $password) {
        // Check if the user is already temporarily locked out (for this specific username)
        if (get_transient('limit_login_' . $username)) {
            return new WP_Error('too_many_attempts', __('تعداد تلاش‌های ورود بیش از حد. لطفاً بعداً دوباره تلاش کنید.', 'wp-login-guard'));
        }

        // Only proceed if it's a failed login attempt for an *existing* user.
        // If $user is already a WP_Error, it means authentication failed.
        // Also ensure it's not a generic username that doesn't exist.
        if ( is_wp_error( $user ) && ( $user->get_error_code() == 'incorrect_password' || $user->get_error_code() == 'invalid_username' || $user->get_error_code() == 'invalid_email' ) ) {

            // Try to get the user by login or email for accurate meta data tracking
            $user_obj = get_user_by( 'login', $username );
            if ( ! $user_obj ) {
                $user_obj = get_user_by( 'email', $username );
            }

            if ( $user_obj && $user_obj->exists() ) {
                $attempts = (int) get_user_meta($user_obj->ID, 'login_attempts', true);
                $attempts++;

                if ($attempts >= 3) { // 3 failed attempts
                    set_transient('limit_login_' . $username, true, 60 * 5); // Lock out for 5 minutes
                    update_user_meta($user_obj->ID, 'login_attempts', 0); // Reset attempts after lockout
                    return new WP_Error('too_many_attempts', __('تعداد تلاش‌های ورود بیش از حد. لطفاً بعداً دوباره تلاش کنید.', 'wp-login-guard'));
                }

                update_user_meta($user_obj->ID, 'login_attempts', $attempts);
            }
        }

        // If authentication was successful, ensure login attempts are reset.
        if ( ! is_wp_error( $user ) && $user->ID ) {
             delete_user_meta($user->ID, 'login_attempts');
        }

        return $user;
    }
    add_filter('authenticate', 'limit_login_attempts', 30, 3);

    /**
     * Resets login attempts count on successful login.
     *
     * @param string  $user_login The user's username.
     * @param WP_User $user       The WP_User object.
     */
    function reset_login_attempts_on_success($user_login, $user) {
        delete_user_meta($user->ID, 'login_attempts');
    }
    add_action('wp_login', 'reset_login_attempts_on_success', 10, 2);

    /**
     * Removes specific error messages from the login page.
     *
     * @param string $error The error message.
     * @return null|string Returns null to hide the error, or the error string.
     */
    function remove_login_errors() {
        return null;
    }
    add_filter('login_errors', 'remove_login_errors');
    ```

4.  وارد پنل مدیریت وردپرس خود شوید، به بخش **"افزونه‌ها"** بروید و افزونه **"افزایش امنیت ورود به وردپرس"** را **فعال کنید**.

### روش ۲: اضافه کردن به فایل functions.php قالب شما

می‌توانید این کد را مستقیماً به فایل `functions.php` قالب فعال خود اضافه کنید. **پیشنهاد اکید می‌شود قبل از انجام این کار، از فایل `functions.php` خود یک پشتیبان (backup) تهیه کنید.**

1.  به مسیر `wp-content/themes/YourThemeName/` بروید (به جای `YourThemeName` نام واقعی قالب فعال خود را قرار دهید).
2.  فایل `functions.php` را باز کنید.
3.  کد زیر را به انتهای فایل (قبل از تگ بستن `?>`، در صورت وجود) اضافه کنید:

    ```php
    /**
     * Limits the number of failed login attempts for a user.
     *
     * @param WP_User|WP_Error $user     WP_User object or WP_Error on failure.
     * @param string           $username The username entered in the login form.
     * @param string           $password The password entered in the login form.
     * @return WP_User|WP_Error
     */
    function limit_login_attempts($user, $username, $password) {
        // Check if the user is already temporarily locked out (for this specific username)
        if (get_transient('limit_login_' . $username)) {
            return new WP_Error('too_many_attempts', 'تعداد تلاش‌های ورود بیش از حد. لطفاً بعداً دوباره تلاش کنید.');
        }

        // Only proceed if it's a failed login attempt for an *existing* user.
        // If $user is already a WP_Error, it means authentication failed.
        // Also ensure it's not a generic username that doesn't exist.
        if ( is_wp_error( $user ) && ( $user->get_error_code() == 'incorrect_password' || $user->get_error_code() == 'invalid_username' || $user->get_error_code() == 'invalid_email' ) ) {

            // Try to get the user by login or email for accurate meta data tracking
            $user_obj = get_user_by( 'login', $username );
            if ( ! $user_obj ) {
                $user_obj = get_user_by( 'email', $username );
            }

            if ( $user_obj && $user_obj->exists() ) {
                $attempts = (int) get_user_meta($user_obj->ID, 'login_attempts', true);
                $attempts++;

                if ($attempts >= 3) { // 3 failed attempts
                    set_transient('limit_login_' . $username, true, 60 * 5); // Lock out for 5 minutes
                    update_user_meta($user_obj->ID, 'login_attempts', 0); // Reset attempts after lockout
                    return new WP_Error('too_many_attempts', 'تعداد تلاش‌های ورود بیش از حد. لطفاً بعداً دوباره تلاش کنید.');
                }

                update_user_meta($user_obj->ID, 'login_attempts', $attempts);
            }
        }

        // If authentication was successful, ensure login attempts are reset.
        if ( ! is_wp_error( $user ) && $user->ID ) {
             delete_user_meta($user->ID, 'login_attempts');
        }

        return $user;
    }
    add_filter('authenticate', 'limit_login_attempts', 30, 3);

    /**
     * Resets login attempts count on successful login.
     *
     * @param string  $user_login The user's username.
     * @param WP_User $user       The WP_User object.
     */
    function reset_login_attempts_on_success($user_login, $user) {
        delete_user_meta($user->ID, 'login_attempts');
    }
    add_action('wp_login', 'reset_login_attempts_on_success', 10, 2);

    // Removes specific error messages from the login page.
    function remove_login_errors() {
        return null;
    }
    add_filter('login_errors', 'remove_login_errors');
    ```

## ملاحظات مهم

* **تجربه کاربری:** کاربران خود را در مورد محدودیت تلاش ورود مطلع کنید تا در صورت قفل شدن، دچار سردرگمی نشوند. پیام خطا عمومی است، بنابراین ممکن است بخواهید یک صفحه پرسش‌های متداول یا اطلاعاتی اضافه کنید.
* **دسترسی مدیر:** اطمینان حاصل کنید که شما به عنوان مدیر، راه‌های جایگزینی برای دسترسی به سایت خود دارید، در صورتی که به طور تصادفی قفل شدید (مثلاً از طریق FTP برای غیرفعال کردن افزونه/کد، یا یک بک‌دور خاص اگر برای مواقع اضطراری پیاده‌سازی کرده‌اید).
* **امنیت مکمل:** این کد حفاظت اولیه در برابر حملات brute-force را فراهم می‌کند. برای امنیت جامع، استفاده از یک افزونه امنیتی اختصاصی که ویژگی‌های بیشتری مانند مسدودسازی IP، reCAPTCHA و گزارش‌های امنیتی ارائه می‌دهد را در نظر بگیرید.

## مشارکت (Contributing)

مشارکت شما خوشایند است! اگر پیشنهاد یا بهبودهایی برای این کد دارید، می‌توانید یک "Pull Request" ایجاد کنید یا "Issue" جدیدی را گزارش دهید.

## مجوز (License)

این پروژه تحت مجوز GPL-2.0-or-later منتشر شده است.
