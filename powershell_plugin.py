import re
import cast.analysers.ua
from cast.analysers import log, CustomObject, create_link

class PowerShellExtension(cast.analysers.ua.Extension):

    def start_analysis(self, options):
        log.info("[PowerShell] Starting analysis.")
        self.objects_by_name = {}

    def start_file(self, file):
        name = file.get_name().lower()
        if not name.endswith(('.ps1', '.psm1')):
            return

        # Create the root object for this file
        if name.endswith('.ps1'):
            type_name = "PowerShellProgram"
        else:
            type_name = "PowerShellModule"

        program = self._create_object(file, type_name, file.get_name())
        self.objects_by_name[file.get_name()] = program

        content = file.read()
        self._extract_functions(content, program)
        self._extract_invocations(content, program)

    def end_analysis(self):
        log.info("[PowerShell] Analysis complete.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _create_object(self, parent, type_name, name, fullname=None):
        obj = CustomObject()
        obj.set_name(name)
        obj.set_type(type_name)
        obj.set_parent(parent)
        if fullname:
            obj.set_fullname(fullname)
        obj.save()
        log.debug(f"[PowerShell] Created {type_name}: {name}")
        return obj

    def _extract_functions(self, content, parent):
        for match in re.finditer(r"function\s+([A-Za-z0-9_-]+)", content):
            func_name = match.group(1)
            func_obj = self._create_object(parent, "PowerShellFunction", func_name)
            self.objects_by_name[func_name.lower()] = func_obj

    def _extract_invocations(self, content, parent):
        for match in re.finditer(r"(?<=\n)\s*([A-Za-z0-9_-]+)\s+", content):
            cmd = match.group(1)
            call_obj = self._create_object(parent, "PowerShellInvocation", cmd)
            # Optional: create link if target function already known
            target = self.objects_by_name.get(cmd.lower())
            if target:
                create_link("callLink", call_obj, target)
                log.debug(f"[PowerShell] Linked invocation -> {cmd}")
