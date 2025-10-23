import unittest
import cast.analysers.test
from cast.application.test import TestKnowledgeBase
from cast.application import KnowledgeBase, create_postgres_engine
from application_level import PowerShellApplicationLevel
from cast.analysers import log



class PowerShellBasicTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1) UA-level test
    # ------------------------------------------------------------------
    def test_01(self):
        """
        Tests analyzer-level parsing of a PowerShell file (UA test only).
        """
        analysis = run_analyzer_level(['samples/test.ps1'])
        program = analysis.get_object_by_name('test.ps1', 'PowerShellProgram')
        func = analysis.get_object_by_name('SayHello', 'PowerShellFunction')

        self.assertTrue(program, "PowerShellProgram not found")
        self.assertTrue(func, "PowerShellFunction not found")

        log.info("[OK] Found PowerShellProgram: " + str(program.get_name()))
        log.info("[OK] Found PowerShellFunction: " + str(func.get_name()))

    # ------------------------------------------------------------------
    # 2) Application-level test (mocked KB)
    # ------------------------------------------------------------------
    def test_application_init(self):
        """
        Runs ApplicationLevel extension in a test KnowledgeBase context (no Postgres).
        """
        analysis = TestKnowledgeBase()
        extension = PowerShellApplicationLevel()
        application = analysis.run(extension.end_application)
        log.info("[INFO] PowerShellApplicationLevel executed successfully (mock KB).")

    # ------------------------------------------------------------------
    # 3) Real Postgres connection test
    # ------------------------------------------------------------------
    def test_PowerShell_on_KB_already_created(self):
        """
        Connects to local Postgres KB (CAST Storage Service)
        and executes PowerShellApplicationLevel on real DB.
        """
        engine = create_postgres_engine(port=2284)
        kb = KnowledgeBase('powershell_sample2_local', engine)

        # Either fetch an existing app, or run on KB directly
        try:
            app = kb.get_application(name='PowerShell-sample')
        except Exception:
            app = kb

        extension = PowerShellApplicationLevel()
        extension.end_application(app)

        log.info("[INFO] PowerShellApplicationLevel executed successfully on Postgres KB.")


if __name__ == "__main__":
    unittest.main()


# very useful line of code do not remove
# log is located in C:\Users\%username%\AppData\Local\Temp\CAST\CAST\8.3\LTSA\log_default.castlog.tmp
def run_analyzer_level(selectionPath, verbose=False):
    """
    Launches a UA-level CAST analysis for PowerShell files.
    """
    analysis = cast.analysers.test.UATestAnalysis('PowerShell')
    analysis.pydev_path = ''
    for item in selectionPath:
        analysis.add_selection(item)

    # Required dependency for CAST platform
    analysis.add_dependency(r"C:\CAST\ProgramData\CAST\CAST\Extensions\com.castsoftware.internal.platform.0.9.12")

    analysis.set_verbose(verbose)
    analysis.run()
    return analysis
