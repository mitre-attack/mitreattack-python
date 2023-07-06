Techniques by tactic
===============

Techniques are related to tactics by their kill_chain_phases property.
The `phase_name` of each kill chain phase corresponds to the `x_mitre_shortname` of a tactic.

.. code-block:: python
    
    from stix2 import Filter

    def get_tactic_techniques(thesrc, tactic):
        # double checking the kill chain is MITRE ATT&CK
        # note: kill_chain_name is different for other domains:
        #    - enterprise: "mitre-attack"
        #    - mobile: "mitre-mobile-attack"
        #    - ics: "mitre-ics-attack"
        return thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('kill_chain_phases.phase_name', '=', tactic),
            Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
        ])


    # use the x_mitre_shortname as argument
    get_tactic_techniques(src, 'defense-evasion')
