<?php
namespace UserMeta;

/**
 * Handle everyting for user profile update and user registration.
 *
 * This class has been also usd by backend profile and users import features.
 *
 * @author Khaled Hossain
 * @since 1.1.7
 */
class UserInsert
{

    /**
     *
     * @var \WP_Error object
     */
    private $errors;

    /**
     *
     * @var string: profile | registration
     */
    private $actionType;

    /**
     *
     * @var string
     */
    private $formName;

    /**
     *
     * @var FormGenerate object
     */
    private $form;

    /**
     *
     * @var array [FieldName => config array]
     */
    private $fields;

    /**
     *
     * @var int
     */
    private $userID;

    /**
     *
     * @var WP_User object
     */
    private $user;

    /**
     * All user's data including meta data.
     *
     * @var array [fieldName => FieldValue]
     */
    private $userData = [];

    /**
     * Only meta data.
     *
     * @var array [fieldName => FieldValue]
     */
    private $metaData = [];

    public function __construct()
    {
        $this->errors = new \WP_Error();
    }

    /**
     * set $this->actionType.
     */
    private function setActionType()
    {
        $this->actionType = ! empty($_REQUEST['action_type']) ? strtolower(esc_attr($_REQUEST['action_type'])) : '';
        
        if ($this->actionType == 'profile-registration') {
            if (is_user_logged_in()) {
                $this->actionType = 'profile';
            } else {
                $this->actionType = 'registration';
            }
        }
        
        if (empty($this->actionType)) {
            $this->errors->add('empty_action_type', __('Action type is empty', $userMeta->name));
        }
    }

    /**
     * Set $this->user and $this->userID.
     */
    private function setUser()
    {
        global $userMeta;
        $this->user = wp_get_current_user();
        
        switch ($this->actionType) {
            case 'profile':
                if (! empty($_REQUEST['user_id'])) {
                    if (current_user_can('edit_users')) {
                        $userID = (int) esc_attr($_REQUEST['user_id']);
                        $this->user = new \WP_User($userID);
                    }
                }
                
                if (! $this->user->exists()) {
                    $this->errors->add('invalid_user', __('Invalid user!', $userMeta->name));
                } else {
                    $this->userID = $this->user->ID;
                }
                
                break;
            
            case 'registration':
                // $cap = 'add_users' 'create_users';
                break;
        }
    }

    /**
     * Set $this->formName.
     */
    private function setFormName()
    {
        global $userMeta;
        
        if (! isset($_REQUEST['form_key'])) {
            $this->errors->add('empty_form_name', __('Form name is empty', $userMeta->name));
        }
        
        $this->formName = ! empty($_REQUEST['form_key']) ? esc_attr($_REQUEST['form_key']) : '';
    }

    /**
     * Set $this->form and $this->fields.
     */
    private function setFormAndFields()
    {
        $this->form = new FormGenerate($this->formName, $this->actionType, $this->userID);
        $this->fields = $this->form->validInputFields();
    }

    /**
     * Sanitize and validate user input.
     *
     * Assume $this->actionType, $this->fields, $this->formName and $this->user already set.
     * Call this function only after calling $this->setForm()
     */
    private function sanitizeFieldsAndSetUserData()
    {
        global $userMeta;
        $userData = [];
        
        /**
         * Assign $fieldName, $field to $userData.
         * Also validating required and unique.
         */
        foreach ($this->fields as $fieldName => $field) {
            $field = apply_filters('user_meta_field_config', $field, $field['id'], $this->formName, $this->userID);
            $field = apply_filters('user_meta_field_config_before_update', $field, $field['id'], $this->formName, $this->userID);
            
            if ($this->actionType == 'profile') {
                if ($fieldName == 'user_login' || ($fieldName == 'user_pass' && empty($_REQUEST['user_pass']))) {
                    continue;
                }
            }
            
            if ($field['field_type'] == 'custom' && isset($field['input_type']) && $field['input_type'] == 'password') {
                if (empty($_REQUEST[$fieldName])) {
                    continue;
                }
            }

            if ( $this->actionType == 'registration' ) {
                if ( $fieldName == 'user_login'  )
                    $username_base = trim(strtolower(substr($_REQUEST['first_name'],0,1)) . strtolower($_REQUEST['last_name']));
                $username = $username_base;
                $i=2;
                while(username_exists( $username ) ) {
                    $username = $username_base . $i;
                    $i++;
                }
                $_REQUEST['user_login'] = $username;
                $_POST['user_login'] = $username;
                $userdata['user_login'] = $username;
            }

            // / Assigning data to $userData
            $userData[$fieldName] = ! empty($_POST[$fieldName]) ? $_POST[$fieldName] : '';
            
            if (is_array($userData[$fieldName]) && count($userData[$fieldName]) == 1 && ! empty($userData[$fieldName])) {
                $userData[$fieldName] = $userData[$fieldName][0];
            }
            
            // Comment out esc_attr which has been added since 1.1.7rc2. esc_attr causes encodin '<' '>' sign for links on rich text
            // if ( $userData[ $fieldName ] && ! is_array( $userData[ $fieldName ] ) )
            // $userData[ $fieldName ] = esc_attr( $userData[ $fieldName ] );
            
            // / Handle non-ajax file upload
            if (in_array($field['field_type'], [
                'user_avatar',
                'file'
            ])) {
                if (isset($_FILES[$fieldName])) {
                    $extensions = ! empty($field['allowed_extension']) ? $field['allowed_extension'] : 'jpg,png,gif';
                    $maxSize = ! empty($field['max_file_size']) ? $field['max_file_size'] * 1024 : 1024 * 1024;
                    $file = $userMeta->fileUpload($fieldName, $extensions, $maxSize);
                    if (is_wp_error($file)) {
                        if ($file->get_error_code() != 'no_file') {
                            $errors->add($file->get_error_code(), $file->get_error_message());
                        }
                    } else {
                        if (is_string($file)) {
                            $umFile = new File($field);
                            $userData[$fieldName] = $file;
                        }
                    }
                }
                
                $userMeta->removeFromFileCache($userData[$fieldName]);
            }
            
            /*
             * Using Field Class
             */
            if (! isset($field['field_value'])) {
                $field['field_value'] = $userData[$fieldName];
            }
            
            $umField = new Field($field['id'], $field, [
                'user_id' => $this->userID,
                'insert_type' => $this->actionType
            ]);
            
            if ($fieldName == 'user_pass' && $this->actionType == 'registration') {
                $umField->addRule('required');
            }
            
            if ($fieldName == 'user_pass' && $this->actionType == 'profile') {
                if (! empty($field['required_current_password'])) {
                    $umField->addRule('current_password');
                }
            }
            
            if (isset($_REQUEST[$fieldName . '_retype'])) {
                $umField->addRule('equals');
            }
            
            if (! $umField->validate()) {
                foreach ($umField->getErrors() as $errKey => $errVal) {
                    $this->errors->add($errKey, $errVal);
                }
            }
        }
        
        $this->userData = $userData;
    }

    /**
     * Set $this->metaData.
     */
    private function setMetaData()
    {
        global $userMeta;
        $metaData = [];
        $wpField = $userMeta->defaultUserFieldsArray();
        
        if (is_array($this->userData)) {
            foreach ($this->userData as $key => $val) {
                $key = is_string($key) ? trim($key) : $key;
                $val = is_string($val) ? trim($val) : $val;
                if (! $key)
                    continue;
                
                if (! isset($wpField[$key]))
                    $metaData[$key] = $val;
            }
        }
        
        $this->metaData = $metaData;
    }

    /**
     * Validate captcha.
     * Run Captcha validation after completed all other validations.
     */
    private function validateCaptcha()
    {
        global $userMeta;
        if ($this->form->hasCaptcha() && ! $userMeta->isValidCaptcha()) {
            $this->errors->add('invalid_captcha', $userMeta->getMsg('incorrect_captcha'));
        }
    }

    /**
     * Check allowed role for security purpose.
     */
    private function validateRole()
    {
        if (isset($this->userData['role'])) {
            $ignoreRole = true;
            
            // $fieldData = $userMeta->getFieldData( @$_REQUEST['role_field_id'] );
            $field = $this->form->getField(@$_REQUEST['role_field_id']);
            if (is_array(@$field['allowed_roles'])) {
                if (in_array($this->userData['role'], $field['allowed_roles'])) {
                    $ignoreRole = false;
                }
            }
            
            if ($ignoreRole) {
                unset($this->userData['role']);
            }
        }
    }

    /**
     * TODO: Need to implement and convert it into object ***.
     *
     *
     * Add or update user
     * @param array $data: data need to update, both userdata and metadata
     * @param int $userID: if not set, user will registered else user update
     */
    public function insertUser($data, $userID = null)
    {
        global $userMeta;

        $this->runHooks();
        
        $userData = [];
        $metaData = [];
        
        $wpField = $userMeta->defaultUserFieldsArray();
        if (is_array($data)) {
            foreach ($data as $key => $val) {
                $key = is_string($key) ? trim($key) : $key;
                $val = is_string($val) ? trim($val) : $val;
                if (! $key)
                    continue;
                
                if (isset($wpField[$key]))
                    $userData[$key] = $val;
                else
                    $metaData[$key] = $val;
            }
            $this->metaData = $metaData;
        }
        
        // sanitize email and user
        if (! empty($userData['user_email'])) {
            $userData['user_email'] = sanitize_email($userData['user_email']);
        }
        
        if (! empty($userData['user_login'])) {
            $userData['user_login'] = sanitize_user($userData['user_login'], true);
        }



        // Case of registration
        if (! $userID) {
            if (! empty($userData['user_email']) && empty($userData['user_login'])) {
                $user_login = $userData['user_email'];
                if (apply_filters('user_meta_username_without_domain', false)) {
                    $user_login = explode('@', $userData['user_email']);
                    $user_login = $user_login[0];
                    if (username_exists($user_login)) {
                        $user_login = $user_login . rand(1, 999);
                    }
                }
                $userData['user_login'] = sanitize_user($user_login, true);
            } elseif (! empty($userData['user_login']) && empty($userData['user_email'])) {
                $userData['user_email'] = is_email($userData['user_login']) ? $userData['user_login'] : '';
            } elseif (empty($userData['user_login']) && empty($userData['user_email'])) {
                $errors->add('empty_login_email', __('Cannot create a user with an empty login name and empty email', $userMeta->name));
            }
            
            if (empty($userData['user_pass'])) {
                $userData['user_pass'] = wp_generate_password(12, false);
                $passwordNag = true;
            }
            
            if ($userMeta->isHookEnable('user_registration_email')) {
                $userData['user_email'] = apply_filters('user_registration_email', $userData['user_email']);
            }
            
            if ($userMeta->isHookEnable('register_post')) {
                do_action('register_post', $userData['user_login'], $userData['user_email'], $errors);
            }
            
            if ($userMeta->isHookEnable('registration_errors')) {
                $errors = apply_filters('registration_errors', $errors, $userData['user_login'], $userData['user_email']);
            }
            
            if (is_wp_error($errors)) {
                if ($errors->get_error_code()) {
                    return $errors;
                }
            }

            $user_id = wp_insert_user($userData);
            if (is_wp_error($user_id)) {
                return $user_id;
            }

            if (! empty($passwordNag)) {
                update_user_option($user_id, 'default_password_nag', true, true);
            } // Set up the Password change nag.
                  
            // Profile Update
        } else {
            $userData['ID'] = $userID;
            $user_id = wp_update_user($userData);
            if (is_wp_error($user_id)) {
                return $user_id;
            }
        }
        
        $userData['ID'] = $user_id;
        
        if (! empty($userData['role']))
            $this->setMultipleRoles($user_id, $userData['role']);
        
        return array_merge($userData, $metaData);
    }

    /**
     * Set multiple role to user
     *
     * wp_update_user() already handle single role.
     * So we only care about multiple role
     *
     * @since 1.3
     * @param int $userID            
     * @param string|array $roles
     *            Comma seperated roles as string othrwise array
     */
    private function setMultipleRoles($userID, $roles)
    {
        /**
         * Exit in case of single role
         */
        if (is_string($roles) && ! strpos($roles, ','))
            return;
        
        if (is_string($roles))
            $roles = explode(',', $roles);
        
        if (! is_array($roles))
            return;
        
        $user = new \WP_User($userID);
        $user->set_role('');
        foreach ($roles as $role)
            $user->add_role($role);
    }

    /**
     * Run action hooks.
     */
    private function runHooks()
    {
        add_action('profile_update', [
            $this,
            '_updateMetaData'
        ]);
        add_action('user_register', [
            $this,
            '_addMetaData'
        ]);
    }

    /**
     * Update user meta data by using action hooks.
     *
     * This method is only called inside this class.
     * Using public visibility because of calling by action hook.
     */
    public function _updateMetaData($user_id)
    {
        if (! empty($this->metaData) && is_array($this->metaData)) {
            foreach ($this->metaData as $key => $val) {
                update_user_meta($user_id, $key, $val);
            }
        }
    }

    /**
     * Add user meta data by using action hooks.
     *
     * This method is only called inside this class.
     * Using public visibility because of calling by action hook.
     */
    public function _addMetaData($user_id)
    {
        if (! empty($this->metaData) && is_array($this->metaData)) {
            foreach ($this->metaData as $key => $val) {
                add_user_meta($user_id, $key, $val);
            }
        }
    }

    /**
     * Update user's data.
     */
    private function userUpdate()
    {
        global $userMeta;
        
        $html = null;
        
        if (! is_user_logged_in()) {
            $this->errors->add('user_not_loggedin', __('User must be logged in to update profile', $userMeta->name));
        }
        
        $this->userData = apply_filters('user_meta_pre_user_update', $this->userData, $this->userID, $this->formName);
        if (is_wp_error($this->userData)) {
            return $userMeta->showError($this->userData);
        }
        
        $response = $this->insertUser($this->userData, $this->userID);
        if (is_wp_error($response)) {
            return $userMeta->showError($response);
        }
        
        $userMeta->showDataFromDB = true;
        
        do_action('user_meta_after_user_update', (object) $response, $this->formName);
        
        $message = $userMeta->getMsg('profile_updated');
        $html = "<div action_type='$this->actionType'>" . $userMeta->showMessage($message) . '</div>';
        
        return $userMeta->printAjaxOutput($html);
    }

    /**
     * Register a new user.
     */
    private function registerUser()
    {
        global $userMeta;
        if(!isset($userData['user_email'])) {
            $userData['user_email'] = $_REQUEST['p_1_e_mail'];
        }

        // / $userData: array.
        $userData = apply_filters('user_meta_pre_user_register', $this->userData);
        if (is_wp_error($userData)) {
            return $userMeta->showError($userData);
        }
        
        $blogData = $userMeta->validateBlogSignup();

        if (is_wp_error($blogData)) {
            return $userMeta->showError($blogData);
        }

        // If add_user_to_blog set true in UserMeta settings panel
        $userID = null;
        if ( is_multisite() ) {
            $registrationSettings = $userMeta->getSettings( 'registration' );
            if ( ! empty( $registrationSettings['add_user_to_blog'] ) ) {
                $user_login = sanitize_user( $userData['user_login'], true );
                $userID		= username_exists( $user_login );
                if ( $userID ) {
                    $blog_id = get_current_blog_id();
                    if ( ! is_user_member_of_blog( $userID, $blog_id ) )
                        add_user_to_blog( $blog_id, $userID, get_option( 'default_role' ) );
                    else
                        $userID	= null;
                }
            }
        }

        // Create Parent account data
        if(isset($_REQUEST['p_1_first_name'])&&($_REQUEST['p_1_first_name']!="")) {
            $parentData=Array();
            $username_base = trim(strtolower(substr($_REQUEST['p_1_first_name'],0,1)) . strtolower($_REQUEST['p_1_last_name']));
            $username = $username_base;
            $i=2;
            while(username_exists( $username ) ) {
                $username = $username_base . $i;
                $i++;
            }
            // Generate parent password
            $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            $password = substr( str_shuffle( $chars ), 0, 10 );
            $parentData['user_login'] = $username;
            $parentData['user_pass'] = $password;
            $parentData['user_email'] = $_REQUEST['p_1_e_mail'];

            $response = $this->insertUser( $parentData, $userID );

            $parentMeta['first_name'] = ucfirst($_REQUEST['p_1_first_name']);
            $parentMeta['last_name'] = ucfirst($_REQUEST['p_1_last_name']);
            $parentMeta['street_address_1'] = $_REQUEST['p_1_street_address_1'];
            $parentMeta['state'] = $_REQUEST['p_1_state'];
            $parentMeta['city'] = $_REQUEST['p_1_city'];
            $parentMeta['zip_code'] = $_REQUEST['p_1_zip_code'];
            $parentMeta['home_tel'] = $_REQUEST['p_1_home_tel'];
            $parentMeta['cell_no'] = $_REQUEST['p_1_cell_no'];
            $parentMeta['user_email'] = $_REQUEST['p_1_e_mail'];
            $parentMeta['user_pass'] = $password;
            global $wpdb;
            $q = $wpdb->get_results( "SELECT plan_monthly_minutes FROM `plans` where plan_id = " . $_REQUEST['plan_id']);
            $parentMeta['plan_monthly_minutes'] = $q[0]->plan_monthly_minutes;
            if ( is_wp_error( $response ) )
                return $userMeta->showError( $response );
            foreach($parentMeta as $meta_key => $meta_value) {
                update_user_meta( $response['ID'], $meta_key, $meta_value );
            }
            $_REQUEST['parent_id'] = $response['ID'];
            if($userData['user_login']==$parentData['user_login']) {
                $userData['user_login'].="S";
            }
            $response_student = $this->insertUser( $userData, $userID );
            if ( is_wp_error( $response_student ) )
                die( $userMeta->showError( $response_student ) );
            $_REQUEST['first_name']=ucfirst($_REQUEST['first_name']);
            $_REQUEST['last_name']=ucfirst($_REQUEST['last_name']);
            foreach($_REQUEST as $meta_key => $meta_value) {
                update_user_meta( $response_student['ID'], $meta_key, $meta_value );
            }
            $_REQUEST['user_login'] = $username;
            $_REQUEST['user_email'] = $_REQUEST['p_1_e_mail'];
            $_REQUEST['user_pass'] = $password;


        } else {
            $response = $this->insertUser( $userData, $userID );
            if ( is_wp_error( $response ) )
                return $userMeta->showError( $response );
            foreach($_REQUEST as $meta_key => $meta_value) {
                update_user_meta( $response['ID'], $meta_key, $meta_value );
            }
        }


        if (! empty($blogData)) {
            $responseBlog = $userMeta->registerBlog($blogData, $userData);
            if (is_wp_error($responseBlog)) {
                return $userMeta->showError($responseBlog);
            }
        }


        // / Allow to populate form data based on DB instead of $_REQUEST
        $userMeta->showDataFromDB = true;
        
        $registrationSettings = $userMeta->getSettings('registration');
        $activation = $registrationSettings['user_activation'];
        if ($activation == 'auto_active') {
            $msg = $userMeta->getMsg('registration_completed');
        } elseif ($activation == 'email_verification') {
            $msg = $userMeta->getMsg('sent_verification_link');
        } elseif ($activation == 'admin_approval') {
            $msg = $userMeta->getMsg('wait_for_admin_approval');
        } elseif ($activation == 'both_email_admin') {
            $msg = $userMeta->getMsg('sent_link_wait_for_admin');
        }
        
        if (! $userMeta->isPro()) {
            // Commented since 1.4
            // wp_new_user_notification($response['ID'], $response['user_pass']);
            wp_new_user_notification($response['ID']);
        }

        if ( $activation == 'auto_active' ) {
            if ( ! empty( $registrationSettings['auto_login'] ) )
                $userMeta->doLogin( $response );
        }

        do_action('user_meta_after_user_register', (object) $response);

        $html = $userMeta->showMessage($msg);
        
        if (isset($responseBlog)) {
            $html .= $userMeta->showMessage($responseBlog);
        }
        
        $role = $userMeta->getUserRole($response['ID']);
        $redirect_to = $userMeta->getRedirectionUrl( null, 'registration', $role );

        if ($userMeta->isHookEnable('registration_redirect')) {
            $redirect_to = apply_filters('registration_redirect', $redirect_to, $response['ID']);
        }


        if ($redirect_to) {
            if (empty($_REQUEST['is_ajax'])) {
                wp_redirect($redirect_to);
                exit();
            }
            
            $timeout = $activation == 'auto_active' ? 3 : 5;
            $html .= $userMeta->jsRedirect($redirect_to, $timeout);
        }
        
        $html = '<div action_type="registration">' . $html . '</div>';
        return $userMeta->printAjaxOutput($html);
    }

    /**
     * Public method for http post processing, handle both registration and profile update.
     */
    public function postInsertUserProcess()
    {
        global $userMeta;

        $this->setActionType();
        $this->setUser();
        $this->setFormName();
        $this->setFormAndFields();
        
        if ($this->formName && $this->form && ! $this->form->isFound()) {
            $this->errors->add('not_found', sprintf(__('Form "%s" is not found.', $userMeta->name), $this->formName));
        }
        
        if (! $this->fields) {
            $this->errors->add('empty_field', __('No field to update', $userMeta->name));
        }


        /*
         * Showing errors
         */
        if($this->fields['user_email']['field_value']==NULL)
            $this->fields['user_email']['field_value'] = $_REQUEST['p_1_e_mail'];

        if ($this->errors->get_error_code()) {
            return $userMeta->ShowError($this->errors);
        }
        
        $this->sanitizeFieldsAndSetUserData();
        $this->setMetaData();

        if ($this->actionType == 'registration')
            $userMeta->validateMultisiteRegistration($this->errors);
        
        if (empty($this->userData)) {
            $this->errors->add('empty_field_value', __('No data to update', $userMeta->name));
        }

        if ( $this->errors->get_error_code() && ($this->errors->get_error_code()!="validate_unique" ) )
            return $userMeta->ShowError( $this->errors );


        $this->validateCaptcha();
        $this->validateRole();

        if ( $this->errors->get_error_code() && ($this->errors->get_error_code()!="validate_unique" ) )
            return $userMeta->ShowError( $this->errors );


        if ($this->actionType == 'registration') {
            $res = $this->registerUser();
        } elseif ($this->actionType == 'profile') {
            return $this->userUpdate();
        }
        ## After user is created, log user in to continue PMPro payment process
        $creds['user_login'] = $_REQUEST['user_login'];
        $creds['user_password'] = $_REQUEST['user_pass'];
        $creds['remember'] = true;
        $user = wp_signon( $creds, false );
        wp_set_current_user($user->ID);
        wp_set_auth_cookie( $user->ID, true, false );
        do_action( 'wp_login', $creds['user_login'] );

        if ( is_wp_error($user) ) {
            echo $user->get_error_message;
        }

        ## Desk.com API process - create user in Desk

        //$desk = include(ABSPATH . "../desk-sandbox-conf.php");
        $desk = include(ABSPATH . "../desk-conf.php");


        $req_url   = 'https://'.$desk['subdomain'].'.desk.com/oauth/request_token';
        $authurl   = 'https://'.$desk['subdomain'].'.desk.com/oauth/authorize';
        $acc_url   = 'https://'.$desk['subdomain'].'.desk.com/oauth/access_token';
        $api_url   = 'https://'.$desk['subdomain'].'.desk.com/api/v2';

        try {
            $oauth = new \OAuth($desk['conskey'], $desk['conssec'], OAUTH_SIG_METHOD_HMACSHA1);
            $oauth->enableDebug();
            $oauth->setToken($desk['access_token'], $desk['access_secret']);
            $phones = [$_REQUEST['p_1_home_tel'], $_REQUEST['p_1_cell_no'], $_REQUEST['home_tel'], $_REQUEST['cell_no'], $_REQUEST['p_2_home_tel'], $_REQUEST['p_2_cell_no']];

            $phones = array_values(array_filter($phones));

            $types = ['home', 'mobile', 'work', 'other'];
            foreach($types as $key => $type) {
                if(isset($phones[$key])) {
                    $desk_phones[$key]['type'] = $type;
                    $desk_phones[$key]['value'] = $phones[$key];
                }
            }
            $desk_phones = json_encode($desk_phones);
            //$desk_phone = ($_REQUEST['p_1_home_tel']==""?$_REQUEST['home_tel']:$_REQUEST['p_1_home_tel']);
            $oauth->fetch("https://".$desk['subdomain'].".desk.com/api/v2/customers", '{"wp_id":"'.$user->id.'","first_name":"'.$_REQUEST['first_name'].'","last_name":"'.$_REQUEST['last_name'].'","phone_numbers":'.$desk_phones.'}', OAUTH_HTTP_METHOD_POST, array('Content-Type' => 'application/json'));
            $json = json_decode($oauth->getLastResponse());

            $desk_id = $json->id;
            update_user_meta( $user->id, 'desk_id', $desk_id );

        } catch(\OAuthException $E) {
            print_r($E);
            die();
        }

        header('location:'.home_url().'/checkout/plan-details');
        exit();
    }

    /**
     * Handle users import by UserImportController
     *
     * @param array $userdata            
     * @param int $userID            
     */
    public function importUsersProcess($userdata, $userID = null)
    {
        $this->userData = $userdata;
        $this->setMetaData();
        
        return $this->insertUser($userdata, $userID);
    }

    /**
     * Validate user's input.
     * Add error to $errors object.
     * Assign sanitized array to $userMetaCache->backend_profile_fields.
     */
    public function validateBackendFieldsProcess($user, &$errors)
    {
        $this->formName = 'wp_backend_profile';
        $this->actionType = 'profile';
        $this->user = $user;
        $this->userID = $user->ID;
        $this->errors = $errors;
        
        $this->setFormAndFields();
        $this->sanitizeFieldsAndSetUserData();
        $this->setMetaData();
        
        if (! $this->errors->get_error_codes()) {
            $this->runHooks();
        }
    }
}