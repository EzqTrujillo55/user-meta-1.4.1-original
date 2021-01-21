<?php
namespace UserMeta;

class PreloadsController
{

    function __construct()
    {
        global $userMeta;
        
        add_action('plugins_loaded', array(
            $this,
            'loadTextDomain'
        ));
        add_filter('user_row_actions', array(
            $this,
            'userProfileLink'
        ), 10, 2);
        
        add_filter('wp_mail_from', array(
            $this,
            'mailFromEmail'
        ));
        add_filter('wp_mail_from_name', array(
            $this,
            'mailFromName'
        ));
        add_filter('wp_mail_content_type', array(
            $this,
            'mailContentType'
        ));
        
        add_action('wp_ajax_um_common_request', array(
            $userMeta,
            'ajaxUmCommonRequest'
        ));
        
        add_action('user_meta_admin_notices', array(
            $this,
            'adminNotices'
        ));
        add_action('admin_notices', array(
            $userMeta,
            'activateLicenseNotice'
        ));
        
        register_activation_hook($userMeta->file, array(
            $this,
            'userMetaActivation'
        ));
        register_deactivation_hook($userMeta->file, array(
            $this,
            'userMetaDeactivation'
        ));
        
        add_filter('xmlrpc_methods', array(
            $this,
            'newXmlRpcMethods'
        ));
        add_action('init', array(
            $this,
            'processPostRequest'
        ), 30);
        
        add_action('wp_ajax_um-debug', array(
            $this,
            'debug'
        ));
        
        add_action('wp_ajax_um_validate_unique_field', array(
            $userMeta,
            'ajaxValidateUniqueField'
        ));
        add_action('wp_ajax_nopriv_um_validate_unique_field', array(
            $userMeta,
            'ajaxValidateUniqueField'
        ));
        add_action('shutdown', array(
            $this,
            'checkWpFooterEnable'
        ));
        
        if ($userMeta->isPro) {
            add_action('wp_ajax_ump_license_validation', array(
                $userMeta,
                'validateProByUrl'
            ));
            add_action('wp_ajax_nopriv_ump_license_validation', array(
                $userMeta,
                'validateProByUrl'
            ));
            add_filter('pre_set_site_transient_update_plugins', array(
                $userMeta,
                'checkForUpdate'
            ));
        } else {
            add_action('user_meta_schedule_event', [
                $this,
                'retrievePromotionalMessages'
            ]);
            add_action('user_meta_admin_notices', [
                $this,
                'showPromotionalMessage'
            ]);
        }
    }

    function loadTextDomain()
    {
        global $userMeta;
        load_plugin_textdomain($userMeta->name, false, basename($userMeta->pluginPath) . '/helpers/languages');
    }


    /**
     * Filter for get_avatar. Allow to change default avatar to custom one.
     *
     * @param type $avatar
     * @param type $id_or_email
     * @param type $size
     * @param type $default
     * @param type $alt
     * @return html img tag
     */
    function getAvatar( $avatar = '', $id_or_email, $size = '96', $default = '', $alt = false ) {
        global $userMeta;

        $safe_alt = ( false === $alt) ? '' : esc_attr( $alt );

        if ( is_numeric( $id_or_email ) )
            $user_id = (int) $id_or_email;
        elseif ( is_string( $id_or_email ) )
            $user_id = email_exists( $id_or_email );
        elseif ( is_object( $id_or_email ) ){
            if ( ! empty( $id_or_email->user_id ) )
                $user_id = (int) $id_or_email->user_id;
            elseif ( ! empty( $id_or_email->comment_author_email ) )
                $user_id = email_exists( $id_or_email->comment_author_email );
        }

        if ( ! isset( $user_id ) ) return $avatar;

        $umAvatar   = get_user_meta( $user_id, 'user_avatar', true );

        $file    = $userMeta->determinFileDir( $umAvatar );
        if ( ! empty( $file ) ) {
            $avatar = "<img alt='{$safe_alt}' src='{$file['url']}' class='avatar avatar-{$size} photo' height='{$size}' width='{$size}' />";
        }

        return $avatar;
    }

    function userProfileLink($actions, $user_object)
    {
        global $userMeta;
        $general = $userMeta->getSettings('general');
        
        if (isset($general['profile_in_admin']) && ! empty($general['profile_page'])) {
            $url = add_query_arg('user_id', $user_object->ID, get_permalink($general['profile_page']));
            $actions['front_profile'] = "<a href=\"$url\" target=\"_blank\">" . __('Profile', $userMeta->name) . "</a>";
        }
        
        return $actions;
    }

    function mailFromEmail($data)
    {
        global $userMeta;
        $general = $userMeta->getSettings('general');
        
        if (! empty($general['mail_from_email'])) {
            if (is_email($general['mail_from_email']))
                return $general['mail_from_email'];
        }
        
        return $data;
    }

    function mailFromName($data)
    {
        global $userMeta;
        $general = $userMeta->getSettings('general');
        
        if (! empty($general['mail_from_name']))
            return $general['mail_from_name'];
        
        return $data;
    }

    function mailContentType($data)
    {
        global $userMeta;
        $general = $userMeta->getSettings('general');
        
        if (! empty($general['mail_content_type']))
            return $general['mail_content_type'];
        
        return $data;
    }

    /**
     * Showing new version availablity notice at user meta admin pages
     */
    function adminNotices()
    {
        global $userMeta;
        
        $currentPlugin = get_site_transient('update_plugins');
        if (isset($currentPlugin->response[$userMeta->pluginSlug])) {
            $plugin = $currentPlugin->response[$userMeta->pluginSlug];
            $path = 'plugins.php#' . str_replace(' ', '-', strtolower($userMeta->title));
            $pluginsPage = is_multisite() ? network_admin_url($path) : admin_url($path);
            echo adminNotice(sprintf(__('There is a new version of %1$s available. Visit <a href="%2$s">Plugins</a> page to update the plugin.', $userMeta->name), "$userMeta->title $plugin->new_version", $pluginsPage), 'warning');
        }
    }

    /**
     * Showing offer for lite version as admin_notice
     */
    public function showPromotionalMessage()
    {
        $messages = getRemoteMessages();
        if (! empty($messages['promotional_message_lite'])) {
            echo adminNotice($messages['promotional_message_lite'], 'info');
        }
    }

    /**
     * Retrieve promotional messages by user_meta_schedule_event
     */
    public function retrievePromotionalMessages()
    {
        retrieveRemoteMessages();
    }



    function fileUploadExtensions( $allowedExtensions ) {
        global $userMeta;

        if ( isset( $_REQUEST['field_id'] ) ) {
            if ( $_REQUEST['field_id'] == 'csv_upload_user_import' ) {
                $allowedExtensions = array("csv");
            } elseif ( $_REQUEST['field_id'] == 'txt_upload_ump_import' ) {
                $allowedExtensions = array("txt");
            } elseif ( strpos( $_REQUEST['field_id'], 'um_field_' ) !== false ) {

                if ( empty( $_REQUEST['form_key'] ) ) return $allowedExtensions;

                $formName = esc_attr( $_REQUEST['form_key'] );

                if ( ! empty( $formName ) ) {
                    $form = new umFormGenerate( $formName, null, null );
                    $validFields = $form->validInputFields();

                    if ( ! empty( $validFields[ $_REQUEST['field_name'] ] ) ) {
                        $field = $validFields[ $_REQUEST['field_name'] ];
                        if ( ! empty( $field['allowed_extension'] ) ) {
                            $allowedExtensions = str_replace( ' ', '', $field['allowed_extension'] );
                            $allowedExtensions = explode( ",", $allowedExtensions );
                        }
                    }
                }
                /*$fieldID = str_replace( "um_field_", "", $_REQUEST['field_id'] );
                $fields = $userMeta->getData( 'fields' );
                if ( isset( $fields[$fieldID]['allowed_extension'] ) ) {
                    $allowedExtensions = str_replace( ' ', '', $fields[$fieldID]['allowed_extension'] );
                    $allowedExtensions = explode( ",", $allowedExtensions );
                }*/
            }
        }

        return $allowedExtensions;
    }


    function fileUploadMaxSize( $sizeLimit ) {
        global $userMeta;

        if ( isset( $_REQUEST['field_id'] ) ) {
            if ( $_REQUEST['field_id'] == 'csv_upload_user_import' ) {
                $sizeLimit = 10 * 1024 * 1024;
            } elseif ( strpos( $_REQUEST['field_id'], 'um_field_' ) !== false ) {
                $fieldID = str_replace( "um_field_", "", $_REQUEST['field_id'] );
                $fields = $userMeta->getData( 'fields' );
                if ( isset( $fields[$fieldID]['max_file_size'] ) )
                    $sizeLimit = $fields[$fieldID]['max_file_size'] * 1024;
            }
        }
        return $sizeLimit;
    }


    function fileUploadOverwrite( $replaceOldFile ) {
        if ( isset( $_REQUEST['field_id'] ) ) {
            if ( $_REQUEST['field_id'] == 'csv_upload_user_import' )
                $replaceOldFile = true;
        }
        return $replaceOldFile;
    }


    function updateFileCache( $fieldName, $filePath ) {
        global $userMeta;
        $cache  = $userMeta->getData( 'cache' );

        $fileCache = isset( $cache['file_cache'] ) ? $cache['file_cache'] : array();
        if ( ! in_array( $filePath, $fileCache ) ) {
            $fileCache[ time() ] = $filePath;
            $cache['file_cache'] = $fileCache;
            $userMeta->updateData( 'cache', $cache );
        }
    }


    /**
     * Run on the plugin activation
     */
    function userMetaActivation()
    {
        includeCapabilities();
        if (! wp_next_scheduled('user_meta_schedule_event'))
            wp_schedule_event(time(), 'daily', 'user_meta_schedule_event');
    }

    /**
     * Run on the plugin deactivation
     */
    function userMetaDeactivation()
    {
        wp_clear_scheduled_hook('user_meta_schedule_event');
    }

    function newXmlRpcMethods($methods)
    {
        global $userMeta;
        $methods['ump.validate'] = array(
            $userMeta,
            'remoteValidationPro'
        );
        
        return $methods;
    }

    /**
     * Process UM post request which need to execute before header sent to browser.
     */
    function processPostRequest()
    {
        global $userMeta;
        
        // Check if it is a valid request.
        if (empty($_POST['um_post_method_nonce']) || empty($_POST['method_name']))
            return;
        
        // Verify the request with nonce validation. method_name is used for nonce generation
        if (! wp_verify_nonce($_POST['um_post_method_nonce'], $_POST['method_name']))
            return $userMeta->process_status = __('Security check', $userMeta->name);
        
        // Call method when need to trigger. Store process status to $userMeta->process_status for further showing message.
        $methodName = $_POST['method_name'];
        $postMethodName = 'post' . ucwords($methodName);
        // $userMeta->um_post_method_status->$methodName = $userMeta->$postMethodName();
        
        $response = $userMeta->$postMethodName();
        
        if (! isset($userMeta->um_post_method_status)) {
            $um_post_method_status = new \stdClass();
            $um_post_method_status->$methodName = $response;
            $userMeta->um_post_method_status = $um_post_method_status;
        } else
            $userMeta->um_post_method_status->$methodName = $response;
    }

    /**
     * Check if wp_footer enabled.
     * We need to store it for serving next request as shotdown action trigger at end
     * Related function: isWpFooterEnabled
     */
    function checkWpFooterEnable()
    {
        set_site_transient('user_meta_is_wp_footer_enabled', true);
    }

    /**
     * Debuging UMP.
     *
     * Write debug code to views/debug.php
     * Access debug output by http://example.com/wp-admin/admin-ajax.php?action=um-debug
     */
    function debug()
    {
        global $userMeta;
        if ($userMeta->isAdmin())
            $userMeta->render('debug');
        
        die();
    }
}