from pythonforandroid.recipe import CythonRecipe

class AlgoModuleRecipe(CythonRecipe):
    version = "1.1.0"
    url = 'https://github.com/electrum-altcoin/AlgoLib/archive/{version}.zip'
    depends = ['setuptools', 'openssl']
    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch, with_flags_in_cc=True):
        """
        Adds openssl recipe to include and library path.
        """
        env = super().get_recipe_env(arch, with_flags_in_cc)
        openssl_recipe = self.get_recipe('openssl', self.ctx)
        env['CFLAGS'] += openssl_recipe.include_flags(arch)
        env['LDFLAGS'] += ' -L{}'.format(self.ctx.get_libs_dir(arch.arch))
        env['LDFLAGS'] += ' -L{}'.format(self.ctx.libs_dir)
        env['LDFLAGS'] += openssl_recipe.link_dirs_flags(arch)
        env['LIBS'] = env.get('LIBS', '') + openssl_recipe.link_libs_flags()
        return env

recipe = AlgoModuleRecipe()
