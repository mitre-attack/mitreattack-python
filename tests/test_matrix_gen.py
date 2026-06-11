# tests/test_matrix_gen.py
#
# WHY THIS FILE EXISTS:
# We found a bug where MatrixEntry and Tactic crash with AttributeError if you
# create them without passing all arguments. These tests prove the bug is real
# (they fail before the fix) and prove the fix works (they pass after).
#
# HOW TESTS WORK IN PYTHON:
# pytest finds every function starting with "test_", runs it, and checks
# that no assertion fails. A test "passes" if it runs to the end without
# crashing. A test "fails" if it crashes or an assert statement is False.

import pytest
from mitreattack.navlayers.exporters.matrix_gen import MatrixEntry, Tactic


# ─────────────────────────────────────────────────────────────
# GROUP 1 — MatrixEntry
#
# MatrixEntry is a simple data container for one cell in the
# ATT&CK matrix (e.g. a technique like T1059). It stores an
# id, a name, a list of platforms, and a score.
#
# The bug: if you skip the 'id' or 'name' argument (or pass None),
# Python never creates the hidden storage slot for that value.
# Later, when anything tries to READ that slot, Python panics.
# ─────────────────────────────────────────────────────────────

class TestMatrixEntryInit:

    def test_no_args_does_not_raise_attributeerror(self):
        """
        Creating MatrixEntry() with NO arguments should be safe.

        WHY THIS MATTERS:
        The constructor signature is MatrixEntry(id=None, name=None, ...).
        All arguments have None as a default, meaning callers are allowed
        to omit them. If omitting them causes an immediate crash just from
        reading a property, the public API is broken.

        WHAT THE BUG LOOKED LIKE (before the fix):
          entry = MatrixEntry()     ← OK so far, object is created
          entry.id                  ← AttributeError: no attribute '_MatrixEntry__id'
                                      because the storage slot was never created

        WHAT THE FIX GUARANTEES:
          self.__id = None   ← runs unconditionally at the top of __init__
          self.__name = None ← same
          Now the storage slot always exists from birth. Reading it gives None,
          not a crash.
        """
        entry = MatrixEntry()
        # Each of these would have raised AttributeError before the fix.
        assert entry.id is None        # __id slot now exists, holds None
        assert entry.name is None      # __name slot now exists, holds None
        assert entry.platforms == []   # __platforms was already safe (list init)
        assert entry.score is None     # __score was already safe (always assigned)

    def test_id_only_reading_name_does_not_crash(self):
        """
        Passing only 'id' and leaving 'name' blank must not crash when
        'name' is later read.

        SCENARIO:
        A caller builds a partial entry -> they know the ID but haven't
        set the display name yet. This is a perfectly valid use of the API.
        Without the fix, reading entry.name would crash because the 'if name
        is not None: self.name = name' block was skipped, leaving no __name slot.

        DEMONSTRATES:
        The bug was not limited to fully-empty construction. It triggered
        whenever ANY individual argument was omitted or None.
        """
        entry = MatrixEntry(id="T1059")
        assert entry.id == "T1059"   # This was already safe (id was provided)
        assert entry.name is None    # This was the crash — now fixed

    def test_name_only_reading_id_does_not_crash(self):
        """
        The mirror case: passing only 'name', reading 'id' must not crash.

        WHY BOTH DIRECTIONS MATTER:
        The bug existed independently for __id and __name -> they were two
        separate conditional assignments. Fixing one without the other would
        still leave a crash on the unfixed side. Testing both directions
        ensures both assignments were corrected.
        """
        entry = MatrixEntry(name="Command and Scripting Interpreter")
        assert entry.name == "Command and Scripting Interpreter"
        assert entry.id is None     # Would have crashed before the fix

    def test_full_construction_behaves_identically_after_fix(self):
        """
        When ALL arguments are provided, the fix must not change any behavior.

        WHY THIS TEST EXISTS:
        The fix adds 'self.__id = None' and 'self.__name = None' at the top
        of __init__. We then immediately overwrite them with real values via
        the setters ('self.id = id'). This test verifies that the unconditional
        None initialization does not interfere with or shadow the real values.

        IN OTHER WORDS: we are checking that adding the initialization lines
        didn't accidentally break the happy path that already worked.
        """
        entry = MatrixEntry(
            id="T1059",
            name="Command and Scripting Interpreter",
            platforms=["Windows", "Linux", "macOS"]
        )
        assert entry.id == "T1059"
        assert entry.name == "Command and Scripting Interpreter"
        assert "Windows" in entry.platforms
        assert "Linux" in entry.platforms

    def test_property_setter_works_after_default_construction(self):
        """
        A user should be able to create an empty object and fill it in later
        using property setters. Both steps must work without errors.

        PATTERN BEING TESTED:
          entry = MatrixEntry()     ← create empty
          entry.id = "T1059"       ← fill in later via the property setter

        Before the fix, step 1 succeeded and step 2 would succeed too — but
        reading entry.id *before* step 2 would crash. This test verifies
        the full "create then populate" workflow is safe.
        """
        entry = MatrixEntry()
        entry.id = "T1059"          # Calling the setter, not raw attribute assignment
        assert entry.id == "T1059"


# ─────────────────────────────────────────────────────────────
# GROUP 2 — Tactic
#
# Tactic is a container for one column in the ATT&CK matrix
# (e.g. "Execution", "Persistence"). It holds:
#   - tactic: a MatrixEntry describing the tactic itself
#   - techniques: a list of technique MatrixEntries in that column
#   - subtechniques: a dict mapping technique ids to their sub-techniques
#
# The bug was IDENTICAL in structure to MatrixEntry: all three
# private attributes (__tactic, __techniques, __subtechniques)
# were only created inside 'if arg is not None' blocks, so a
# Tactic() with any missing argument was an AttributeError trap.
# ─────────────────────────────────────────────────────────────

class TestTacticInit:

    def test_no_args_does_not_raise_attributeerror(self):
        """
        Creating Tactic() with NO arguments should be completely safe.

        This is the most direct proof of the bug. Before the fix:
          tac = Tactic()            ← object created
          tac.tactic                ← AttributeError immediately
          tac.techniques            ← AttributeError immediately
          tac.subtechniques         ← AttributeError immediately

        All three private attributes (__tactic, __techniques, __subtechniques)
        had the same flaw: they only got created if the matching argument
        was not None. Tactic() passes None for all three, so none of the
        'if' blocks ran, leaving three missing slots.

        After the fix, all three are initialized to None unconditionally
        at the top of __init__ before any conditional logic runs.
        """
        tac = Tactic()
        assert tac.tactic is None           # __tactic slot now guaranteed to exist
        assert tac.techniques is None       # __techniques slot now guaranteed to exist
        assert tac.subtechniques is None    # __subtechniques slot now guaranteed to exist

    def test_tactic_only_other_attributes_do_not_crash(self):
        """
        When only 'tactic' is provided, reading 'techniques' and
        'subtechniques' must return None, not raise AttributeError.

        REAL-WORLD RELEVANCE:
        An external library user might build a Tactic progressively —
        they attach the tactic entry first and add techniques later.
        Without the fix, the moment they try to check tac.techniques
        to see if it's empty, the program crashes. This test covers
        that exact workflow.
        """
        # We need a MatrixEntry to use as the tactic argument.
        # This also confirms MatrixEntry's own fix is in place (test independence).
        fake_tactic_entry = MatrixEntry(id="TA0002", name="Execution")

        tac = Tactic(tactic=fake_tactic_entry)

        assert tac.tactic is fake_tactic_entry   # Was safely set via the setter
        assert tac.techniques is None            # Was never set → must be None, not crash
        assert tac.subtechniques is None         # Same

    def test_full_construction_behaves_identically_after_fix(self):
        """
        When ALL arguments are provided, Tactic must work exactly as before.

        Same rationale as TestMatrixEntryInit.test_full_construction_behaves_identically:
        the 'self.__tactic = None' lines we added get overwritten immediately
        by real values. This test confirms the overwrite happens correctly
        and the object's final state is exactly what the caller passed in.
        """
        entry = MatrixEntry(id="TA0002", name="Execution")

        tac = Tactic(
            tactic=entry,
            techniques=[],        # Empty list is valid — "no techniques yet"
            subtechniques={}      # Empty dict is valid — "no subtechniques yet"
        )

        assert tac.tactic is entry         # Object identity check, not just equality
        assert tac.techniques == []        # List correctly stored
        assert tac.subtechniques == {}     # Dict correctly stored
