<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 *
 * @package    symfony
 * @subpackage plugin
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id$
 */
class BasesfGuardAuthActions extends genericActions
{
  public function executeSignin($request)
  {
    $user = $this->getUser();
    if ($user->isAuthenticated())
    {
      return $this->redirect('homepage');
    }

    $class = sfConfig::get('app_sf_guard_plugin_signin_form', 'sfGuardFormSignin');

    if( $username = $user->getAttribute('new_username', '') )
    {
      $user->setAttribute('new_username', null );
    }
    $this->form = new $class(['username' => $username ]);

    if( $request->isMethod('post') && $request->hasParameter('signin') )
    {
      $this->form->bind($request->getParameter('signin'));
      if ($this->form->isValid())
      {
        $values = $this->form->getValues();

        if( $this->getUser()->requiresPasswordUpdate() )
        {
          return $this->redirect('setup', ['section' => 'password']);
        }

        $this->getUser()->signin($values['user'], array_key_exists('remember', $values) ? $values['remember'] : false);

        // always redirect to a URL set in app.yml
        // or to the referer
        // or to the homepage
        $signin_url = sfConfig::get('app_sf_guard_plugin_success_signin_url', $user->getReferer( $request->getReferer() ) );

        $redirect_url = 'homepage';
        if( $signin_url != '')
        {
          $chosen_app  = explode('.', $_SERVER['HTTP_HOST'] )[ 0 ];
          $referer_app = explode('.', parse_url( $signin_url )['host'] )[ 0 ];

          $redirect_url = $chosen_app == $referer_app ? $signin_url : $redirect_url;
        }
        return $this->redirect( $redirect_url );
      }
      $this->getUser()->addFlash('error', 'Login failed, please retry', false );
    }
    else
    {
      if ($request->isXmlHttpRequest())
      {
        $this->getResponse()->setHeaderOnly(true);
        $this->getResponse()->setStatusCode(401);

        return sfView::NONE;
      }

      // if we have been forwarded, then the referer is the current URL
      // if not, this is the referer of the current request
      if( $request->isMethod( sfRequest::GET ) )
      { // Only setReferrer for non-post/put requests as these can't be redirected to after signin
        $uri = $request->getUri();
        if( substr( $uri, -5 ) == '.json')
        { // Strip json suffixes from uris before saving as referer
          $uri = substr( $uri, 0, -5 );
        }
        $user->setReferer($this->getContext()->getActionStack()->getSize() > 1 ? $uri : $request->getReferer());
      }

      $module = sfConfig::get('sf_login_module');
      if ($this->getModuleName() != $module)
      {
        return $this->redirect($module.'/'.sfConfig::get('sf_login_action'));
      }
      $this->getResponse()->setStatusCode(401);
    }
  }

  public function executeSignout($request)
  {
    $this->getUser()->signOut();

    $signoutUrl = sfConfig::get('app_sf_guard_plugin_success_signout_url', $request->getReferer());

    $this->redirect('' != $signoutUrl ? $signoutUrl : 'homepage');
  }

  public function executeSecure($request)
  {
    $this->getResponse()->setStatusCode(403);
  }

  public function executePassword($request)
  {
    throw new sfException('This method is not yet implemented.');
  }
}
