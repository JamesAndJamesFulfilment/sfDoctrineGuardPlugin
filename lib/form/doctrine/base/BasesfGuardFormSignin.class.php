<?php

/**
 * BasesfGuardFormSignin
 *
 * @package    sfDoctrineGuardPlugin
 * @subpackage form
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: BasesfGuardFormSignin.class.php 23536 2009-11-02 21:41:21Z Kris.Wallsmith $
 */
class BasesfGuardFormSignin extends BaseForm
{
    /**
     * @see sfForm
     */
    public function setup()
    {
        $this->setWidgets([
            'username' => new sfWidgetFormInputText(),
            'password' => new sfWidgetFormInputPassword(['type' => 'password']),
        ]);

        $this->setValidators([
            'username' => new sfValidatorString(),
            'password' => new sfValidatorString(['trim' => false]),
        ]);

        $this->validatorSchema->setPostValidator(new sfGuardValidatorUser());

        $this->widgetSchema->setNameFormat('signin[%s]');
    }
}
