import cast_upgrade_1_6_17  # @UnusedImport
import cast.application
from cast.analysers import log, CustomObject

class PowerShellApplicationLevel(cast.application.ApplicationLevelExtension):

    def end_application_create_objects(self, application):
        """
        Called before end_application().
        Use this to define and register custom object types if needed.
        """
        log.info("Defining PowerShell object types...")
        application.declare_type("PowerShellProgram")
        application.declare_type("PowerShellFunction")

    def end_application(self, application):
        log.info("Starting Application level Analysis for PowerShell...")

        # Reading the intermediate file created by the analyzer
        exchange_file = self.get_intermediate_file('com.castsoftware.powershell.txt')

        try:
            with open(exchange_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    parts = line.strip().split(";")
                    if parts[0] == "SCRIPT":
                        obj = CustomObject()
                        obj.set_name(parts[1])
                        obj.set_type("PowerShellProgram")
                        obj.set_fullname(parts[1])
                        obj.save()
                        log.info("Created PowerShellProgram: %s" % parts[1])
                    elif parts[0] == "FUNCTION":
                        obj = CustomObject()
                        obj.set_name(parts[1])
                        obj.set_type("PowerShellFunction")
                        obj.set_fullname(parts[1])
                        obj.save()
                        log.info("Created PowerShellFunction: %s" % parts[1])
        except Exception as e:
            log.warning(e)("Error reading intermediate file: %s" % e)

        log.info("End of Application level Analysis for PowerShell.")

    def _my_internal_utility_method(self, exchange_file):
        # Tu peux mettre ici des traitements plus complexes ou des regroupements d’objets
        pass
