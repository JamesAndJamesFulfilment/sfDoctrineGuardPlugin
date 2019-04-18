<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Create a new user.
 */
class sfGuardCreateUserTask extends sfGuardUserCreateTask
{
  /**
   * @see sfTask
   */
  protected function configure()
  {

      parent::configure();

    $this->name = 'create-user';

    $this->detailedDescription = <<<EOF
The [guard:create-user|INFO] task creates a user:

  [./symfony guard:create-user mail@example.com fabien password Fabien POTENCIER|INFO]
EOF;
  }
}
