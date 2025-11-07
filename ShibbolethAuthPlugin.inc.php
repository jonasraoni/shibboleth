<?php

/**
 * @file plugins/generic/shibboleth/ShibbolethAuthPlugin.inc.php
 *
 * Copyright (c) 2017 Simon Fraser University
 * Copyright (c) 2017 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class ShibbolethAuthPlugin
 * @ingroup plugins_generic_shibboleth
 *
 * @brief Shibboleth authentication plugin.
 *
 * Assumes Apache mod_shib and appropriate configuration.
 */

import('lib.pkp.classes.plugins.GenericPlugin');

class ShibbolethAuthPlugin extends GenericPlugin {
	// @todo: Is there a way to disable delete and upgrade actions when the user does not have permission to disable?
	// @todo: The profile password tab should just be hidden completely when the plugin is enabled.
	public const REQUIRED_SETTINGS = ["shibbolethWayfUrl", "shibbolethHeaderUin", "shibbolethHeaderFirstName", "shibbolethHeaderEmail"];

	/** @var int */
	private $_contextId;
	/** @var bool */
	private $_isSiteWide;

	/**
	 * @copydoc Plugin::register()
	 */
	public function register($category, $path, $mainContextId = null) {
		if(!parent::register($category, $path, $mainContextId)) {
			return false;
		}

		$this->addLocaleData();
		if (!$this->getEnabled() || !$this->isShibbolethConfigured() || !Config::getVar('general', 'installed')) {
			return true;
		}

		$this->_isSiteWide = $this->getSetting(CONTEXT_SITE, 'enabled');
		$this->_contextId = $this->_isSiteWide ? CONTEXT_SITE : $this->getCurrentContextId();
		// Register pages to handle login.
		HookRegistry::register('LoadHandler',	[$this, 'handleRequest']);
		// Register callback for smarty filters
		HookRegistry::register('TemplateManager::display', [$this, 'handleTemplateDisplay']);
		return true;
	}

	/**
	 * @copydoc Plugin::getName()
	 */
	public function getName() {
		return 'ShibbolethAuthPlugin';
	}

	/**
	 * @copydoc Plugin::getDisplayName()
	 */
	public function getDisplayName() {
		return __('plugins.generic.shibboleth.displayName');
	}

	/**
	 * @copydoc Plugin::getDescription()
	 */
	public function getDescription() {
		return __('plugins.generic.shibboleth.description');
	}

	/**
	 * @copydoc Plugin::isSitePlugin()
	 */
	public function isSitePlugin() {
		return true;
	}

	/**
	 * @copydoc Plugin::manage()
	 */
	public function manage($args, $request) {
		if ($request->getUserVar('verb') !== 'settings') {
			return parent::manage($args, $request);
		}

		AppLocale::requireComponents(LOCALE_COMPONENT_APP_COMMON, LOCALE_COMPONENT_PKP_MANAGER);
		$templateMgr = TemplateManager::getManager($request);
		$templateMgr->register_function('plugin_url', [$this, 'smartyPluginUrl']);
		$this->import('ShibbolethSettingsForm');
		$form = new ShibbolethSettingsForm($this, $this->_contextId);
		if ($request->getUserVar('save')) {
			$form->readInputData();
			if ($form->validate()) {
				$form->execute();
				return new JSONMessage(true);
			}
		} else {
			$form->initData();
		}

		return new JSONMessage(true, $form->fetch($request));
	}

	/**
	 * @copydoc Plugin::getSetting()
	 */
	public function getSetting($contextId, $name) {
		return parent::getSetting($this->_isSiteWide ? CONTEXT_SITE : $contextId, $name);
	}

	/**
	 * @copydoc Plugin::getActions()
	 */
	public function getActions($request, $verb) {
		$actions = parent::getActions($request, $verb);
		// Don’t allow settings unless enabled in this context.
		if (!$this->getEnabled() || !$this->getCanDisable()) {
			return $actions;
		}

		$router = $request->getRouter();
		$url = $router->url($request, null, null, 'manage', null, ['verb' => 'settings', 'plugin' => $this->getName(), 'category' => 'generic']);
		import('lib.pkp.classes.linkAction.request.AjaxModal');
		array_unshift(
			$actions,
			new LinkAction(
				'settings',
				new AjaxModal($url, $this->getDisplayName()),
				__('manager.plugins.settings')
			)
		);
		return $actions;
	}

	/**
	 * @copydoc Plugin::getCanEnable()
	 */
	public function getCanEnable() {
		return !$this->_isSiteWide || $this->_contextId == CONTEXT_SITE;
	}

	/**
	 * @copydoc Plugin::getCanDisable()
	 */
	public function getCanDisable() {
		return !$this->_isSiteWide || $this->_contextId == CONTEXT_SITE;
	}

	/**
	 * @copydoc Plugin::setEnabled()
	 */
	public function setEnabled($enabled) {
		$this->updateSetting($this->_contextId, 'enabled', $enabled, 'bool');
	}
	/**
	 * Determine whether or not this plugin is currently enabled.
	 * @param $contextId integer is ignored
	 * @return boolean
	 */
	public function getEnabled($contextId = null) {
		return $this->getSetting($this->_contextId, 'enabled');
	}

	/**
	 * @copydoc Plugin::isShibbolethConfigured()
	 * Determine whether or not this plugin is currently configured.
	 * @return boolean
	 */
	public function isShibbolethConfigured(): bool {
		foreach (static::REQUIRED_SETTINGS as $setting){
			if (!$this->getSetting($this->_contextId, $setting)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Hook callback: register pages for each login method.
	 * This URL is of the form: shibboleth/{$shibrequest}
	 * @see PKPPageRouter::route()
	 */
	public function handleRequest(string $hookName, array $params): bool {
		[$page, $op] = $params;
		$isShibbolethOptional = $this->getSetting($this->_contextId, 'shibbolethOptional');
		$pageOperationMap = [
			'shibboleth' => [$op],
			// If Shibboleth is required, override functionalities
			'login' => array_merge(
				['index', 'signIn', 'signOut'],
				$isShibbolethOptional ? [] : ['changePassword', 'lostPassword', 'requestResetPassword', 'savePassword']
			),
			'user' => ['activateUser', 'register', 'registerUser', 'validate']
		];
		if (!$this->getEnabled() || array_search($op, $pageOperationMap[$page] ?? []) === false) {
			return false;
		}

		$this->import('pages/ShibbolethHandler');
		define('HANDLER_CLASS', 'ShibbolethHandler');
		return true;
	}

	/**
	 * Hook callback: register output filter for user registration
	 * @see TemplateManager::display()
	 */
	public function handleTemplateDisplay(string $hookName, array $args): bool {
		/** @var TemplateManager */
		[$templateMgr, $template] = $args;
		if (in_array($template, ['frontend/pages/userRegister.tpl', 'frontend/pages/userLogin.tpl'])) {
			$templateMgr->registerFilter("output", function ($output, $templateMgr) use ($template) {
				return $this->registrationAndLoginFilter($output, $templateMgr, $template === 'frontend/pages/userRegister.tpl');
			});
		}

		return false;
	}

	/**
	 * Output filter adds Shibboleth interaction to registration and login form.
	 */
	public function registrationAndLoginFilter(string $output, Smarty_Internal_Template $templateMgr, bool $isRegistration): string {
		$htmlId = $isRegistration ? "register" : "login";
		if (!preg_match("/<form[^>]+id=\"{$htmlId}\"[^>]+>/i", $output, $matches, PREG_OFFSET_CAPTURE)) {
			return $output;
		}

		$shibbolethOptionalTitle = $this->getSetting($this->_contextId, 'shibbolethOptionalTitle');
		$shibbolethOptionalButtonLabel = $this->getSetting($this->_contextId, 'shibbolethOptionalButtonLabel');
		$shibbolethOptionalDescription = $this->getSetting($this->_contextId, $isRegistration ? 'shibbolethOptionalRegistrationDescription' : 'shibbolethOptionalLoginDescription');
		[$match, $offset] = $matches[0];
		$request = Application::get()->getRequest();
		$templateMgr->assign([
			'shibbolethLoginUrl' => $this->_getShibbolethLoginUrl($request),
			'shibbolethTitle' => $shibbolethOptionalTitle,
			'shibbolethButtonLabel' => $shibbolethOptionalButtonLabel,
			'shibbolethDescription' => $shibbolethOptionalDescription,
			'isRegistration' => $isRegistration,
		]);
		$newOutput = substr($output, 0, $offset + strlen($match));
		$newOutput .= $templateMgr->fetch($this->getTemplateResource('shibbolethProfile.tpl'));
		$newOutput .= substr($output, $offset + strlen($match));
		$output = $newOutput;
		$templateMgr->unregisterFilter('output', [$this, 'registrationFilter']);
		return $output;
	}

	/**
	 * Get the Shibboleth plugin object
	 */
	public static function getPlugin(): ShibbolethAuthPlugin {
		/** @var ShibbolethAuthPlugin $plugin */
		$plugin = PluginRegistry::getPlugin('generic', 'ShibbolethAuthPlugin');
		return $plugin;
	}

	/**
	 * Generate Shibboleth Request Url
	 */
	private function _getShibbolethLoginUrl(Request $request): string {
		$this->_contextId = $this->getCurrentContextId();
		$wayfUrl = $this->getSetting($this->_contextId, 'shibbolethWayfUrl');
		// FIX: Build proper base URL without current page path
		$context = $request->getContext();
		$contextPath = ($context ? $context->getPath() : 'index') . '/';
		// Build the complete target URL from scratch
		$protocol = $request->getProtocol();
		$host = $request->getServerHost();
		$baseUrl = $protocol . '://' . $host;
		$target = '?target=' . urlencode("{$baseUrl}/index.php/{$contextPath}shibboleth/login");
		// Handle different wayfUrl formats
		if (preg_match('#^(https?:)?//#i', $wayfUrl)) {
			$url = (strpos($wayfUrl, '//') === 0 ? 'https:' : '') . $wayfUrl;
			$parsed = parse_url($url);
			$hostFromConfig = $parsed['host'] ?? '';
			$hostFromRequest = $request->getServerHost();
			return $wayfUrl . (!strcasecmp($hostFromConfig, $hostFromRequest) ? $target : '');
		}

		// Handle absolute paths (start with '/')
		if (strpos($wayfUrl, '/') === 0) {
			return $wayfUrl . $target;
		}

		// Handle relative paths
		return '/' . ltrim($wayfUrl, '/') . $target;
	}
}
