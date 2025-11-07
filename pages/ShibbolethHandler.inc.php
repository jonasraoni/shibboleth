<?php

/**
 * @file plugins/generic/shibboleth/pages/ShibbolethHandler.inc.php
 *
 * Copyright (c) 2017 Simon Fraser University
 * Copyright (c) 2017 John Willinsky
 * Distributed under the GNU GPL v3 or later. For full terms see the file docs/COPYING.
 *
 * @class ShibbolethHandler
 * @ingroup plugins_generic_shibboleth
 *
 * @brief Handle Shibboleth responses
 */

import('classes.handler.Handler');

class ShibbolethHandler extends Handler {
	/** @var ShibbolethAuthPlugin */
	private $_plugin;
	/** @var int */
	private $_contextId;

	/**
	 * Constructor
	 */
	public function __construct() {
		parent::__construct();
		$this->_plugin = ShibbolethAuthPlugin::getPlugin();
		$this->_contextId = $this->_plugin->getCurrentContextId();
	}

	/**
	* Intercept normal login/registration requests and defer to Shibboleth
	*/
	public function activateUser(array $args, Request $request): void {
		$this->_shibbolethRedirect($request);
	}

	/**
	* @copydoc ShibbolethHandler::activateUser()
	*/
	public function changePassword($args, $request): void {
		$this->_shibbolethRedirect($request);
	}

	/**
	* @copydoc ShibbolethHandler::activateUser()
	* @param Request $request
	*/
	public function index($args, $request): void {
		$this->_checkOptionalShibboleth($request);
		/**
		 * This section is based off the code found in
		 * pkp-lib's LoginHandler.inc.php
		 * https://github.com/pkp/pkp-lib/blob/f64f302f8bef4f6c2e40275af717884c643f995b/pages/login/LoginHandler.inc.php#L37-L68
		 */
		$this->setupTemplate($request);
		if (Validation::isLoggedIn()) {
			$this->sendHome($request);
		}

		if (Config::getVar('security', 'force_login_ssl') && $request->getProtocol() != 'https') {
			// Force SSL connections for login
			$request->redirectSSL();
		}

		$templateMgr = TemplateManager::getManager($request);
		$templateMgr->assign([
			'loginMessage' => $request->getUserVar('loginMessage'),
			'username' => $request->getUserVar('username'),
			'remember' => $request->getUserVar('remember'),
			'source' => $request->getUserVar('source'),
			'showRemember' => Config::getVar('general', 'session_lifetime') > 0,
		]);

		// For force_login_ssl with base_url[...]: make sure SSL used for login form
		$loginUrl = $request->url(null, 'login', 'signIn');
		if (Config::getVar('security', 'force_login_ssl')) {
			$loginUrl = PKPString::regexp_replace('/^http:/', 'https:', $loginUrl);
		}

		$templateMgr->assign('loginUrl', $loginUrl);
		$templateMgr->display('frontend/pages/userLogin.tpl');
	}

	/**
	 * Send the user "home" (typically to the dashboard, but that may not always be available).
	 */
	public function sendHome(Request $request): void {
		$request->redirect(null, $request->getContext() ? 'submissions' : 'user');
	}

	/**
	 * @copydoc ShibbolethHandler::activateUser()
	 */
	public function lostPassword(?array $args, Request $request): void {
		$this->_shibbolethRedirect($request);
	}

	/**
	 * @copydoc ShibbolethHandler::activateUser()
	 */
	public function register(?array $args, Request $request): void {
		$this->_checkOptionalShibboleth($request);
		if (Config::getVar('security', 'force_login_ssl') && $request->getProtocol() != 'https') {
			// Force SSL connections for registration
			$request->redirectSSL();
		}

		// If the user is logged in, show them the registration success page
		if (Validation::isLoggedIn()) {
			$this->setupTemplate($request);
			$templateMgr = TemplateManager::getManager($request);
			$templateMgr->assign('pageTitle', 'user.login.registrationComplete');
			$templateMgr->display('frontend/pages/userRegisterComplete.tpl');
			return;
		}

		$this->validate(null, $request);
		$this->setupTemplate($request);

		import('lib.pkp.classes.user.form.RegistrationForm');
		$regForm = new RegistrationForm($request->getSite());

		// Initial GET request to register page
		if (!$request->isPost()) {
			$regForm->initData();
			$regForm->display($request);
			return;
		}

		// Form submitted
		$regForm->readInputData();
		if (!$regForm->validate()) {
			$regForm->display($request);
			return;
		}

		$regForm->execute();

		// Inform the user of the email validation process. This must be run
		// before the disabled account check to ensure new users don't see the
		// disabled account message.
		if (Config::getVar('email', 'require_validation')) {
			$this->setupTemplate($request);
			$templateMgr = TemplateManager::getManager($request);
			$templateMgr->assign([
				'requireValidation' => true,
				'pageTitle' => 'user.login.registrationPendingValidation',
				'messageTranslated' => __('user.login.accountNotValidated', ['email' => $regForm->getData('email')]),
			]);
			$templateMgr->display('frontend/pages/message.tpl');
			return;
		}

		$reason = null;
		if (Config::getVar('security', 'implicit_auth')) {
			Validation::login('', '', $reason);
		} else {
			Validation::login($regForm->getData('username'), $regForm->getData('password'), $reason);
		}

		if ($reason !== null) {
			$this->setupTemplate($request);
			$templateMgr = TemplateManager::getManager($request);
			$templateMgr->assign([
				'pageTitle' => 'user.login',
				'errorMsg' => $reason==''?'user.login.accountDisabled':'user.login.accountDisabledWithReason',
				'errorParams' => ['reason' => $reason],
				'backLink' => $request->url(null, 'login'),
				'backLinkLabel' => 'user.login',
			]);
			$templateMgr->display('frontend/pages/error.tpl');
			return;
		}

		$source = $request->getUserVar('source');
		if (preg_match('#^/\w#', $source) === 1) {
			$request->redirectUrl($source);
		} else {
			// Make a new request to update cookie details after login
			$request->redirect(null, 'user', 'register');
		}
	}

	/**
	 * @copydoc ShibbolethHandler::activateUser()
	 */
	public function registerUser(?array $args, Request $request): void {
		$this->register($args, $request);
	}

	/**
	 * @copydoc ShibbolethHandler::activateUser()
	 */
	public function requestResetPassword(?array $args, Request $request): void {
		$this->_shibbolethRedirect($request);
	}

	/**
	 * @copydoc ShibbolethHandler::activateUser()
	 */
	public function savePassword(?array $args, Request $request): void {
		$this->_shibbolethRedirect($request);
	}

	/**
	 * Log out the user and redirect to the login page.
	 */
	private function _logout(): void {
		Validation::logout();
		Validation::redirectLogin();
	}

	/**
	 * Login handler; receives post-validation Shibboleth redirect.
	 */
	public function login(?array $args, Request $request): void {
		$user = $this->_getUserFromShibboleth($isNewUser);
		if (!$user) {
			$this->_logout();
		}

		$this->_checkAdminStatus($user);
		$disabledReason = null;
		$success = Validation::registerUserSession($user, $disabledReason);
		if (!$success) {
			error_log("Disabled user " . $user->getAuthStr() . " attempted Shibboleth login" . ($disabledReason ? ": $disabledReason" : ""));
			$this->_logout();
		}

		// Sends the user to the profile page after registration to select its roles
		if ($isNewUser) {
			$context = $request->getContext();
			$request->redirect($context ? $context->getPath() : 'index', 'user', 'profile', null, null, 'roles');
		}

		$this->_redirectAfterLogin($request);
	}

	/**
	 * @copydoc ShibbolethHandler::activateUser()
	 */
	public function signIn(?array $args, Request $request): void {
		$this->_checkOptionalShibboleth($request);
		/**
		 * This section is based off the code found in
		 * pkp-lib's LoginHandler.inc.php
		 * https://github.com/pkp/pkp-lib/blob/f64f302f8bef4f6c2e40275af717884c643f995b/pages/login/LoginHandler.inc.php#L90-L133
		 */
		$this->setupTemplate($request);
		if (Validation::isLoggedIn()) $this->sendHome($request);

		if (Config::getVar('security', 'force_login_ssl') && $request->getProtocol() != 'https') {
			// Force SSL connections for login
			$request->redirectSSL();
		}

		$user = Validation::login($request->getUserVar('username'), $request->getUserVar('password'), $reason, $request->getUserVar('remember') == null ? false : true);
		if ($user !== false) {
		if ($user->getMustChangePassword()) {
				// User must change their password in order to log in
				Validation::logout();
				$request->redirect(null, null, 'changePassword', $user->getUsername());
			} else {
				$source = $request->getUserVar('source');
				$redirectNonSsl = Config::getVar('security', 'force_login_ssl') && !Config::getVar('security', 'force_ssl');
				if (preg_match('#^/\w#', $source) === 1) {
					$request->redirectUrl($source);
				}
				if ($redirectNonSsl) {
					$request->redirectNonSSL();
				} else {
					$this->_redirectAfterLogin($request);
				}
			}
		} else {
			$templateMgr = TemplateManager::getManager($request);
			$templateMgr->assign([
				'username' => $request->getUserVar('username'),
				'remember' => $request->getUserVar('remember'),
				'source' => $request->getUserVar('source'),
				'showRemember' => Config::getVar('general', 'session_lifetime') > 0,
				'error' => $reason === null ? 'user.login.loginError' : ($reason === '' ? 'user.login.accountDisabled' : 'user.login.accountDisabledWithReason'),
				'reason' => $reason,
			]);
			$templateMgr->display('frontend/pages/userLogin.tpl');
		}
	}

	/**
	 * Intercept normal logout; redirect to context home page instead
	 * of login (which would send back to Shibboleth again).
	 */
	public function signOut(?array $args, Request $request): void {
		$context = $this->getTargetContext($request);
		$router = $request->getRouter();
		Validation::logout();
		$contextPath = is_null($context) ? "" : $context->getPath();
		$returnUrl = $router->url($request, $contextPath);
		$request->redirectUrl($returnUrl);
	}

	/**
	 * @copydoc ShibbolethHandler::activateUser()
	 */
	public function validate($requiredContexts = null, $request = null): void {
		import('lib.pkp.pages.user.RegistrationHandler');
		$registrationHandler = new RegistrationHandler();
		$registrationHandler->initialize($request);
		$registrationHandler->validate($requiredContexts, $request);
	}

	/**
	 * Check if the user should be an admin according to the Shibboleth plugin settings, and adjust the User object accordingly.
	 */
	private function _checkAdminStatus(User $user): void {
		$adminsStr = $this->_plugin->getSetting($this->_contextId, 'shibbolethAdminUins');
		$admins = explode(' ', $adminsStr);

		$uin = $user->getAuthStr();
		if (!$uin) {
			return;
		}

		$userId = $user->getId();
		$adminFound = array_search($uin, $admins);

		/** @var UserGroupDAO $userGroupDao */
		$userGroupDao = DAORegistry::getDAO('UserGroupDAO');

		// should be unique
		$adminGroup = $userGroupDao->getByRoleId(0, ROLE_ID_SITE_ADMIN)->next();
		$adminId = $adminGroup->getId();

		// If they are in the list of users who should be admins
		if ($adminFound !== false) {
			// and if they are not already an admin
			if (!$userGroupDao->userInGroup($userId, $adminId)) {
				error_log("Shibboleth assigning admin to {$uin}");
				$userGroupDao->assignUserToGroup($userId, $adminId);
			}
		} else {
			// If they are not in the admin list - then be sure they
			// are not an admin in the role table
			error_log("Removing admin for {$uin}");
			$userGroupDao->removeUserFromGroup($userId, $adminId, 0);
		}
	}

	/**
	 * @copydoc LoginHandler::_redirectAfterLogin
	 */
	private function _redirectAfterLogin(Request $request): void {
		$context = $this->getTargetContext($request);
		// If there's a context, send them to the dashboard after login.
		if ($context && $request->getUserVar('source') == '' &&
			array_intersect(
				[ROLE_ID_SITE_ADMIN, ROLE_ID_MANAGER, ROLE_ID_SUB_EDITOR, ROLE_ID_AUTHOR, ROLE_ID_REVIEWER, ROLE_ID_ASSISTANT],
				(array) $this->getAuthorizedContextObject(ASSOC_TYPE_USER_ROLES)
			)) {
			$request->redirect($context->getPath(), 'dashboard');
		}

		$request->redirectHome();
	}

	/**
	 * Create a new user from the Shibboleth-provided information
	 */
	private function _getUserFromShibboleth(?bool &$isNewUser = null): ?User {
		$uin = $this->_getShibbolethSetting('shibbolethHeaderUin');
		$userEmail = $this->_getShibbolethSetting('shibbolethHeaderEmail');

		// We rely on these headers being present.
		if ($uin === null || $userEmail === null) {
			error_log("Shibboleth plugin enabled, but not properly configured; the {$uin} and {$userEmail} are required");
			return null;
		}

		/** @var UserDAO $userDao */
		$userDao = DAORegistry::getDAO('UserDAO');
		// Try to locate the user by UIN or email
		$user = $userDao->getUserByAuthStr($uin) ?? $userDao->getUserByEmail($userEmail);
		if ($user) {
			// Set/validate UIN
			if (!$user->getAuthStr()) {
				$user->setAuthStr($uin);
				$userDao->updateObject($user);
			} elseif ($user->getAuthStr() !== $uin) {
				error_log("Shibboleth user with email {$userEmail} already has a different UIN");
				return null;
			}
			return $user;
		}

		// Create a new user
		$userFirstName = $this->_getShibbolethSetting('shibbolethHeaderFirstName');
		$userLastName = $this->_getShibbolethSetting('shibbolethHeaderLastName');
		// optional values
		$userPhone = $this->_getShibbolethSetting('shibbolethHeaderPhone');
		$userMailing = $this->_getShibbolethSetting('shibbolethHeaderMailing');
		if (empty($uin) || empty($userEmail) || empty($userFirstName) || empty($userLastName)) {
			error_log("Shibboleth failed to find all required fields to create a new user");
			return null;
		}

		$user = $userDao->newDataObject();
		$user->setAuthStr($uin);
		$user->setUsername($userEmail);
		$user->setEmail($userEmail);
		// Get the site primary locale, needed for setting the given name and family name of the user.
		$request = Application::get()->getRequest();
		$site = $request->getSite();
		$sitePrimaryLocale = $site->getPrimaryLocale();
		$user->setGivenName($userFirstName, $sitePrimaryLocale);
		$user->setFamilyName($userLastName, $sitePrimaryLocale);

		if (!empty($userPhone)) {
			$user->setPhone($userPhone);
		}

		if (!empty($userMailing)) {
			$user->setMailingAddress($userMailing);
		}

		$user->setDateRegistered(Core::getCurrentDate());
		$user->setPassword(Validation::encryptCredentials(Validation::generatePassword(40), Validation::generatePassword(40)));
		$userDao->insertObject($user);
		$isNewUser = true;
		error_log("Shibboleth failed to find a user with UIN {$uin} or the email {$userEmail}, a new user was created");
		return $user;
	}

	/**
	 * Intercept normal login/registration requests; defer to Shibboleth.
	 */
	private function _shibbolethRedirect(Request $request): void {
		$request->redirectUrl($this->_shibbolethLoginUrl($request));
	}

	/**
	 * Generate Shibboleth Request Url
	 */
	private function _shibbolethLoginUrl(Request $request): string {
		$wayfUrl = $this->_plugin->getSetting($this->_contextId, 'shibbolethWayfUrl');
		$router = $request->getRouter();
		$context = $request->getContext();
		$contextPath = $context ? $context->getPath() : null;
		$loginUrl = $router->url($request, $contextPath, 'shibboleth', 'login', null, null, null, true);
		return $wayfUrl . '?target=' . urlencode($loginUrl);
	}

	/**
	 * Check if the Shibboleth plugin is optional
	 */
	private function _checkOptionalShibboleth(Request $request): void {
		$isOptional = $this->_plugin->getSetting($this->_contextId, 'shibbolethOptional');
		if (!$isOptional) {
			$this->_shibbolethRedirect($request);
		}
	}

	/**
	 * Get a setting from the plugin
	 */
	private function _getShibbolethSetting(string $setting) {
		return $_SERVER[$this->_plugin->getSetting($this->_contextId, $setting) ?? ''] ?? null;
	}
}
