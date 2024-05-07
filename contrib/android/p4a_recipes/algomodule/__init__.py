from pythonforandroid.toolchain import CythonRecipe

class AlgoModuleRecipe(CythonRecipe):
    version = "1.1.0"
    url = 'https://github.com/electrum-altcoin/AlgoLib/archive/{version}.zip'

recipe = AlgoModuleRecipe()
