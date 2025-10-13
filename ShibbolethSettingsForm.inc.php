<?php

/**
 * @file plugins/generic/shibboleth/ShibbolethSettingsForm.inc.php
 *
 * Copyright (c) 2017 Simon Fraser University
 * Copyright (c) 2017 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class ShibbolethSettingsForm
 * @ingroup plugins_generic_shibboleth
 *
 * @brief Form for managers to modify Shibboleth
 * authentication plugin settings
 */

import('lib.pkp.classes.form.Form');

class ShibbolethSettingsForm extends Form {

	/** @var int */
	private $_contextId;

	/** @var ShibbolethAuthPlugin */
	private $_plugin;

	private const SETTINGS = [
		'shibbolethWayfUrl' => 'string',
		'shibbolethHeaderUin' => 'string',
		'shibbolethHeaderFirstName' => 'string',
		'shibbolethHeaderLastName' => 'string',
		'shibbolethHeaderEmail' => 'string',
		'shibbolethHeaderPhone' => 'string',
		'shibbolethHeaderMailing' => 'string',
		'shibbolethAdminUins' => 'string',
		'shibbolethOptional' => 'bool',
		'shibbolethOptionalTitle' => 'string',
		'shibbolethOptionalLoginDescription' => 'string',
		'shibbolethOptionalRegistrationDescription' => 'string',
		'shibbolethOptionalButtonLabel' => 'string'
	];

	/**
	 * Constructor
	 */
	public function __construct(ShibbolethAuthPlugin $plugin, ?int $contextId) {
		$this->_contextId = $contextId;
		$this->_plugin = $plugin;
		parent::__construct($plugin->getTemplateResource('settingsForm.tpl'));
		$this->addCheck(new FormValidatorPost($this));
		$this->addCheck(new FormValidatorCSRF($this));
		foreach (ShibbolethAuthPlugin::REQUIRED_SETTINGS as $setting) {
			$this->addCheck(new FormValidator($this, $setting, 'required', 'plugins.generic.shibboleth.manager.settings.' . $setting . 'Required'));
		}
	}

	/**
	 * @copydoc Form::initData()
	 */
	public function initData() {
		foreach (array_keys(static::SETTINGS) as $setting) {
			$this->setData($setting, $this->_plugin->getSetting($this->_contextId, $setting));
		}
	}

	/**
	 * @copydoc Form::readInputData()
	 */
	public function readInputData() {
		$this->readUserVars(array_keys(static::SETTINGS));
	}

	/**
	 * @copydoc Form::fetch()
	 */
	public function fetch($request, $template = null, $display = false) {
		$templateMgr = TemplateManager::getManager($request);
		$templateMgr->assign('pluginName', $this->_plugin->getName());
		return parent::fetch($request, $template, $display);
	}

	/**
	 * @copydoc Form::readInputData()
	 */
	public function execute(...$functionArgs) {
		foreach (static::SETTINGS as $setting => $type) {
			$value = $this->getData($setting);
			if (in_array($setting, ['shibbolethWayfUrl', 'shibbolethHeaderUin', 'shibbolethHeaderFirstName', 'shibbolethHeaderLastName', 'shibbolethHeaderEmail', 'shibbolethHeaderPhone', 'shibbolethHeaderMailing', 'shibbolethAdminUins'])) {
				$value = trim($value, "\"\';");
			}

			$this->_plugin->updateSetting($this->_contextId, $setting, $value, $type);
		}

		return parent::execute(...$functionArgs);
	}
}
