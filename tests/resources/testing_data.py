import json

compat = {
    "name": "layer",
    "versions": {"attack": "10", "navigator": "4.5.5", "layer": "4.3"},
    "domain": "enterprise-attack",
    "description": "а б в г ґ д е є ж з и і ї й к л м н о п р с т у ф х ц ч ш щ ь ю я",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Azure AD",
            "Office 365",
            "SaaS",
            "IaaS",
            "Google Workspace",
            "PRE",
            "Network",
            "Containers",
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": False,
        "showName": True,
        "showAggregateScores": False,
        "countUnscored": False,
    },
    "hideDisabled": False,
    "techniques": [],
    "gradient": {"colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"], "minValue": 0, "maxValue": 100},
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False,
    "selectVisibleTechniques": False,
}
agg_layer_1 = """
{
    "name": "example1",
    "description": "aggregation function: average. Negative score in sub-technique hides aggregation number in parent tooltip, but, updates color",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "selectTechniquesAcrossTactics": false,
    "domain": "enterprise-attack",
    "layout": {
        "layout": "side",
        "showID": false,
        "showName": true,
        "showAggregateScores": true
    },
    "techniques": [
        {
            "techniqueID": "T1548",
            "tactic": "privilege-escalation",
            "showSubtechniques": true,
            "score": 100
        },
        {
            "techniqueID": "T1548.001",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.002",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.003",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.004",
            "tactic": "privilege-escalation",
            "score": -100000000
        }
    ]
}"""

agg_layer_2 = """
{
    "name": "example2",
    "description": "aggregation function: min. Score of 0 should (but does not) take the minimum",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "selectTechniquesAcrossTactics": false,
    "domain": "enterprise-attack",
    "layout": {
        "layout": "side",
        "showID": false,
        "showName": true,
        "showAggregateScores": true,
        "aggregateFunction": "min"
    },
    "techniques": [
        {
            "techniqueID": "T1548",
            "tactic": "privilege-escalation",
            "showSubtechniques": true,
            "score": 100
        },
        {
            "techniqueID": "T1548.001",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.002",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.003",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.004",
            "tactic": "privilege-escalation",
            "score": 0
        }
    ]
}
"""

agg_layer_3 = """
{
    "name": "example3",
    "description": "aggregation function: min. Score of -100 apparently takes minimum according to color, but the aggregate score tooltip is hidden",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "selectTechniquesAcrossTactics": false,
    "domain": "enterprise-attack",
    "layout": {
        "layout": "side",
        "showID": false,
        "showName": true,
        "showAggregateScores": true,
        "aggregateFunction": "min"
    },
    "techniques": [
        {
            "techniqueID": "T1548",
            "tactic": "privilege-escalation",
            "showSubtechniques": true,
            "score": 100
        },
        {
            "techniqueID": "T1548.001",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.002",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.003",
            "tactic": "privilege-escalation",
            "score": 100
        },
        {
            "techniqueID": "T1548.004",
            "tactic": "privilege-escalation",
            "score": -100
        }
    ]
}"""

agg_layer_5 = """
{
    "name": "example5",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "domain": "enterprise-attack",
    "description": "bug: score of 0 with min function doesn't display in tooltip of parent technique",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Office 365",
            "Azure AD",
            "AWS",
            "GCP",
            "Azure",
            "SaaS",
            "PRE",
            "Network"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "min",
        "showID": false,
        "showName": true,
        "showAggregateScores": true,
        "countUnscored": false
    },
    "hideDisabled": false,
    "techniques": [
        {
            "techniqueID": "T1548",
            "tactic": "privilege-escalation",
            "score": 0,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": true,
            "aggregateScore": 0
        },
        {
            "techniqueID": "T1548.001",
            "tactic": "privilege-escalation",
            "score": 100,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false,
            "aggregateScore": 100
        }
    ],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "showTacticRowBackground": false,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": true,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false,
}"""

agg_layer_6 = """
{
    "name": "example6",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "domain": "enterprise-attack",
    "description": "bug: score of 0 on sub-technique with min function hides aggregate score tooltip and color on parent technique",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Office 365",
            "Azure AD",
            "AWS",
            "GCP",
            "Azure",
            "SaaS",
            "PRE",
            "Network"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "min",
        "showID": false,
        "showName": true,
        "showAggregateScores": true,
        "countUnscored": false
    },
    "hideDisabled": false,
    "techniques": [
        {
            "techniqueID": "T1098",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": true,
            "aggregateScore": 0
        },
        {
            "techniqueID": "T1098.002",
            "tactic": "persistence",
            "score": 0,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false,
            "aggregateScore": 0
        },
        {
            "techniqueID": "T1098.001",
            "tactic": "persistence",
            "score": 100,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false,
            "aggregateScore": 100
        }
    ],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "showTacticRowBackground": false,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": true,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false,
}
"""

agg_layer_7 = """
{
    "name": "example7",
    "description": "",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "selectTechniquesAcrossTactics": false,
    "domain": "enterprise-attack",
    "layout": {
        "layout": "side",
        "showID": false,
        "showName": true,
        "showAggregateScores": true,
        "aggregateFunction": "average"
    },
    "techniques": [
        {
            "techniqueID": "T1548",
            "tactic": "privilege-escalation",
            "showSubtechniques": true,
            "score": 100
        },
        {
            "techniqueID": "T1548.001",
            "tactic": "privilege-escalation",
            "score": 0
        },
        {
            "techniqueID": "T1548.002",
            "tactic": "privilege-escalation",
            "score": 0
        },
        {
            "techniqueID": "T1548.003",
            "tactic": "privilege-escalation",
            "score": 0
        },
        {
            "techniqueID": "T1548.004",
            "tactic": "privilege-escalation",
            "score": 0
        }
    ]
}"""

example_layer_v3 = """
{
    "name": "example layer",
    "version": "3.0",
    "domain": "mitre-enterprise",
    "description": "hello, world",
    "filters": {
        "stages": [
            "act"
        ],
        "platforms": [
            "Windows",
            "macOS"
        ]
    },
    "sorting": 2,
    "layout": {
        "layout": "side",
        "showName": true,
        "showID": true
    },
    "hideDisabled": true,
    "techniques": [
        {
            "techniqueID": "T1110",
            "color": "#fd8d3c",
            "comment": "This is a comment for technique T1110",
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1110.001",
            "comment": "This is a comment for T1110.001 - the first subtechnique of technique T1110.001"
        },
        {
            "techniqueID": "T1134",
            "tactic": "defense-evasion",
            "score": 75,
            "comment": "this is a comment for T1134 which is only applied on the defense-evasion tactic"
        },
        {
            "techniqueID": "T1033",
            "enabled": false
        },
        {
            "techniqueID": "T1053",
            "tactic": "privilege-escalation",
            "metadata": [
                {
                    "name": "T1053 metadata1",
                    "value": "T1053 metadata1 value"
                },
                {
                    "name": "T1053 metadata2",
                    "value": "T1053 metadata2 value"
                }
            ]
        }
    ],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {
            "label": "Legend Item Label",
            "color": "#FF00FF"
        }
    ],
    "showTacticRowBackground": true,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": false,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false,
    "metadata": [
        {
            "name": "layer metadata 1",
            "value": "layer metadata 1 value"
        },
        {
            "name": "layer metadata 2",
            "value": "layer metadata 2 value"
        }
    ]
}
"""

example_layer_v3_longer = """
    {
    "name": "test layer name",
    "version": "3.0",
    "domain": "mitre-enterprise",
    "description": "test layer description which has some additional words and is quite long",
    "filters": {
        "stages": [
            "act"
        ],
        "platforms": [
            "Windows",
            "Linux",
            "macOS"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "showID": false,
        "showName": true
    },
    "hideDisabled": false,
    "techniques": [
        {
            "techniqueID": "T1015",
            "tactic": "persistence",
            "color": "#756bb1",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1015",
            "tactic": "privilege-escalation",
            "color": "#756bb1",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1138",
            "tactic": "persistence",
            "color": "",
            "comment": "comment",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1138",
            "tactic": "privilege-escalation",
            "color": "#778833",
            "comment": "comment",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1197",
            "tactic": "defense-evasion",
            "score": 3,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1197",
            "tactic": "persistence",
            "score": 3,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1088",
            "tactic": "defense-evasion",
            "score": 25,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1088",
            "tactic": "privilege-escalation",
            "score": 25,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1191",
            "tactic": "defense-evasion",
            "score": 44,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1191",
            "tactic": "execution",
            "score": 44,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1116",
            "tactic": "defense-evasion",
            "score": 123,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059",
            "tactic": "execution",
            "score": 2,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1109",
            "tactic": "defense-evasion",
            "score": 16,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1109",
            "tactic": "persistence",
            "score": 16,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1122",
            "tactic": "defense-evasion",
            "color": "#ffaabb",
            "comment": "test comment 3",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1122",
            "tactic": "persistence",
            "color": "",
            "comment": "test comment 3",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1503",
            "tactic": "credential-access",
            "score": 18,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1140",
            "tactic": "defense-evasion",
            "score": 8,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1482",
            "tactic": "discovery",
            "color": "#bcbddc",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1157",
            "tactic": "persistence",
            "score": 61,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1157",
            "tactic": "privilege-escalation",
            "score": 61,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1212",
            "tactic": "credential-access",
            "color": "",
            "comment": "comment another one",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1083",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1046",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1201",
            "tactic": "discovery",
            "color": "#636363",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1552.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.004",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.006",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        }
    ],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {
            "label": "legend1",
            "color": "#d396f7"
        },
        {
            "label": "longer legend",
            "color": "#9ccce2"
        },
        {
            "label": "legend3",
            "color": "#62c487"
        }
    ],
    "metadata": [],
    "showTacticRowBackground": false,
    "tacticRowBackground": "#4400ff",
    "selectTechniquesAcrossTactics": false,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false,
}
"""

example_layer_v3_all = """{
    "name": "layer",
    "version": "3.0",
    "domain": "mitre-enterprise",
    "description": "",
    "filters": {
        "stages": [
            "act"
        ],
        "platforms": [
            "Windows",
            "Linux",
            "macOS"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "showID": false,
        "showName": true
    },
    "hideDisabled": true,
    "techniques": [
        {
            "techniqueID": "T1266",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1247",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1277",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1329",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1307",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1308",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1330",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1310",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1332",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1275",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1293",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1288",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1301",
            "tactic": "organizational-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1287",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1294",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1300",
            "tactic": "organizational-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1289",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1297",
            "tactic": "people-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1303",
            "tactic": "organizational-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1295",
            "tactic": "people-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1306",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1229",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1236",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1224",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1299",
            "tactic": "organizational-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1302",
            "tactic": "organizational-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1296",
            "tactic": "people-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1298",
            "tactic": "organizational-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1238",
            "tactic": "priority-definition-direction",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1228",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1347",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1349",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1341",
            "tactic": "persona-development",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1328",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1352",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1391",
            "tactic": "persona-development",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1343",
            "tactic": "persona-development",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1321",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1312",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1334",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1354",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1254",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1226",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1253",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1279",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1268",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1249",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1339",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1345",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1232",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1355",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1231",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1320",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1230",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1284",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1260",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1245",
            "tactic": "target-selection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1285",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1250",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1259",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1258",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1243",
            "tactic": "target-selection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1242",
            "tactic": "target-selection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1282",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1244",
            "tactic": "target-selection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1241",
            "tactic": "target-selection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1227",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1342",
            "tactic": "persona-development",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1350",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1255",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1379",
            "tactic": "stage-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1394",
            "tactic": "stage-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1326",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1286",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1311",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1333",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1262",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1261",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1344",
            "tactic": "persona-development",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1364",
            "tactic": "stage-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1234",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1365",
            "tactic": "stage-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1314",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1233",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1280",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1272",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1283",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1225",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1270",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1248",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1278",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1267",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1269",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1271",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1348",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1263",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1274",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1276",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1246",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1265",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1264",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1389",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1256",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1336",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1252",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1273",
            "tactic": "people-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1257",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1322",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1315",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1316",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1390",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1309",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1331",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1318",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1319",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1313",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1392",
            "tactic": "persona-development",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1396",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1251",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1281",
            "tactic": "organizational-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1346",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1363",
            "tactic": "stage-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1353",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1305",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1335",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1304",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1239",
            "tactic": "priority-definition-direction",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1235",
            "tactic": "priority-definition-planning",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1351",
            "tactic": "build-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1291",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1290",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1358",
            "tactic": "test-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1337",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1338",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1317",
            "tactic": "adversary-opsec",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1340",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1397",
            "tactic": "technical-information-gathering",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1237",
            "tactic": "priority-definition-direction",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1240",
            "tactic": "priority-definition-direction",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1393",
            "tactic": "test-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1356",
            "tactic": "test-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1357",
            "tactic": "test-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1359",
            "tactic": "test-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1360",
            "tactic": "test-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1292",
            "tactic": "technical-weakness-identification",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1361",
            "tactic": "test-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1362",
            "tactic": "stage-capabilities",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1327",
            "tactic": "establish-&-maintain-infrastructure",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1548.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1134.005",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1531",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1087",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1087.001",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1087.002",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1087.003",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1087.004",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1098",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1098.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1098.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1098.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1098.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1071",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1071.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1071.002",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1071.003",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1071.004",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1010",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1560",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1560.001",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1560.002",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1560.003",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1123",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1119",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1020",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1197",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1197",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.005",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.005",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.006",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.006",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.007",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.007",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.008",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.008",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.009",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.009",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.010",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.010",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.011",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547.011",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.005",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037.005",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1217",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1176",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1110",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1110.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1110.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1110.003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1110.004",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1115",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1538",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1526",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059.001",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059.002",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059.003",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059.004",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059.005",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059.006",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1059.007",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1092",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1554",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1136",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1136.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1136.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1136.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1543.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1555",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1555.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1555.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1555.003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1485",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1132",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1132.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1132.002",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1486",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1565",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1565.001",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1565.002",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1565.003",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1001.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1001.002",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1001.003",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1074",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1074.001",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1074.002",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1030",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1530",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1213",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1213.001",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1213.002",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1005",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1039",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1025",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1491",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1491.001",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1491.002",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1140",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1006",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1561",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1561.001",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1561.002",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1482",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1189",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1568",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1568.002",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1568.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1568.003",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1114",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1114.001",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1114.002",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1114.003",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1573",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1573.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1573.002",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1499",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1499.001",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1499.002",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1499.003",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1499.004",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.005",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.005",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.006",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.006",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.007",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.007",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.008",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.008",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.009",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.009",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.010",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.010",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.011",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.011",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.012",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.012",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.013",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.013",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.014",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.014",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.015",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1546.015",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1480",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1480.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1048",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1048.001",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1048.002",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1048.003",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1041",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1011",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1011.001",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1052",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1052.001",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1567",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1567.001",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1567.002",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1190",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1203",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1211",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1068",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1210",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1133",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1133",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1008",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1083",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1222",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1222.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1222.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1495",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1187",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1484",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1484",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1200",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1564",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1564.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1564.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1564.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1564.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1564.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1564.006",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.010",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.010",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.010",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.005",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.005",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.011",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.011",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.011",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.009",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.009",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.009",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.007",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.007",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.007",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.008",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.008",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.008",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.006",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.006",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.006",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.012",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.012",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1574.012",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1562",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1562.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1562.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1562.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1562.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1562.006",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1562.007",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1525",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1070.006",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1202",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1105",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1490",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.001",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.002",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.003",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.004",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1056.004",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1559",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1559.001",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1559.002",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1534",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1570",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1185",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1557",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1557",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1557.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1557.001",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1036",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1036.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1036.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1036.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1036.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1036.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1036.006",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556.003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1556.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1578",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1578.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1578.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1578.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1578.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1112",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1104",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1106",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1498",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1498.001",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1498.002",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1046",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1135",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1040",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1040",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1095",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1571",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.006",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.007",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.008",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.005",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1003.004",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1027",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1027.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1027.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1027.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1027.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1027.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1137",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1137.006",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1137.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1137.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1137.005",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1137.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1137.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1201",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1120",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1069",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1069.002",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1069.003",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1069.001",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1566",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1566.001",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1566.002",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1566.003",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1542.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1057",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.005",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.008",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.008",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.009",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.009",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.011",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.011",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.013",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.013",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.012",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.012",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.014",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1055.014",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1572",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1090",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1090.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1090.002",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1090.003",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1090.004",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1012",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1219",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1563",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1563.001",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1563.002",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021.001",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021.002",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021.003",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021.004",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021.005",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1021.006",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1018",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1091",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1091",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1496",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1207",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1014",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.002",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.005",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.005",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.005",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.001",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.004",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.003",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1053.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1029",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1113",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1505",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1505.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1505.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1505.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1489",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1129",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.011",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.005",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.009",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.010",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.007",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1218.008",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1216",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1216.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1072",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1072",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1518",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1518.001",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1528",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1539",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1558",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1558.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1558.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1558.003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1553",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1553.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1553.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1553.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1553.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1195",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1195.001",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1195.002",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1195.003",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1082",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1016",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1049",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1033",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1007",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1569",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1569.001",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1569.002",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1529",
            "tactic": "impact",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1124",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1080",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1221",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1205",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1205",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1205",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1205.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1205.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1205.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1537",
            "tactic": "exfiltration",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1127",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1127.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1199",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1111",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.001",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.002",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.003",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.004",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.005",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1552.006",
            "tactic": "credential-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1535",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.002",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.003",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.001",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1550.004",
            "tactic": "lateral-movement",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1204",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1204.001",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1204.002",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.001",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.001",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.001",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.002",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.002",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.002",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.003",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.003",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.003",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.004",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.004",
            "tactic": "persistence",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.004",
            "tactic": "privilege-escalation",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1078.004",
            "tactic": "initial-access",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1125",
            "tactic": "collection",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497.001",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497.001",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497.002",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497.002",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497.003",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1497.003",
            "tactic": "discovery",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1102",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1102.001",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1102.002",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1102.003",
            "tactic": "command-and-control",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1047",
            "tactic": "execution",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1220",
            "tactic": "defense-evasion",
            "color": "",
            "comment": "",
            "enabled": false,
            "metadata": [],
            "showSubtechniques": false
        }
    ],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "showTacticRowBackground": false,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": true,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false,
}"""

example_layer_v41 = """
{
    "name": "example layer",
    "versions": {
        "attack": "8",
        "navigator": "4.1",
        "layer": "4.1"
    },
    "domain": "enterprise-attack",
    "description": "hello, world",
    "filters": {
        "platforms": [
            "Windows",
            "macOS"
        ]
    },
    "sorting": 2,
    "layout": {
        "layout": "side",
        "showName": true,
        "showID": false
    },
    "hideDisabled": false,
    "techniques": [
        {
            "techniqueID": "T1110",
            "color": "#fd8d3c",
            "comment": "This is a comment for technique T1110",
            "showSubtechniques": true
        },
        {
            "techniqueID": "T1110.001",
            "comment": "This is a comment for T1110.001 - the first subtechnique of technique T1110.001"
        },
        {
            "techniqueID": "T1134",
            "tactic": "defense-evasion",
            "score": 75,
            "comment": "this is a comment for T1134 which is only applied on the defense-evasion tactic"
        },
        {
            "techniqueID": "T1078",
            "tactic": "discovery",
            "enabled": false
        },
        {
            "techniqueID": "T1053",
            "tactic": "privilege-escalation",
            "metadata": [
                {
                    "name": "T1053 metadata1",
                    "value": "T1053 metadata1 value"
                },
                {
                    "divider": true
                },
                {
                    "name": "T1053 metadata2",
                    "value": "T1053 metadata2 value"
                }
            ]
        }
    ],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {
            "label": "Legend Item Label",
            "color": "#FF00FF"
        }
    ],
    "showTacticRowBackground": true,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": false,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false,
    "metadata": [
        {
            "name": "layer metadata 1",
            "value": "layer metadata 1 value"
        },
        {
            "name": "layer metadata 2",
            "value": "layer metadata 2 value"
        }
    ]
}
"""

example_layer_v41_vbug = """{
    "name": "example_layer",
    "versions": {
        "attack": "9",
        "navigator": "8.2",
        "layer": "9.0"
    },
    "domain": "enterprise-attack",
    "description": "",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Office 365",
            "Azure AD",
            "AWS",
            "GCP",
            "Azure",
            "SaaS",
            "Bagles"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "showID": false,
        "showName": true
    },
    "hideDisabled": false,
    "techniques": [
        {
            "techniqueID": "T1197",
            "tactic": "defense-evasion",
            "score": 255,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1197",
            "tactic": "persistence",
            "score": 255,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547",
            "tactic": "persistence",
            "color": "#fc3b3b",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1547",
            "tactic": "privilege-escalation",
            "color": "#fc3b3b",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037",
            "tactic": "persistence",
            "color": "#fc3b3b",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1037",
            "tactic": "privilege-escalation",
            "color": "#fc3b3b",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1140",
            "tactic": "defense-evasion",
            "score": 11,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1006",
            "tactic": "defense-evasion",
            "score": 55,
            "color": "",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        },
        {
            "techniqueID": "T1106",
            "tactic": "execution",
            "color": "#fc3b3b",
            "comment": "",
            "enabled": true,
            "metadata": [],
            "showSubtechniques": false
        }
    ],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "showTacticRowBackground": false,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": true,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false,
}"""

example_layer_v3_dict = {
    "name": "example layer",
    "version": "3.0",
    "domain": "enterprise-attack",
    "description": "hello, world",
    "filters": {"platforms": ["Windows", "macOS"]},
    "sorting": 2,
    "layout": {"layout": "side", "showName": True, "showID": False},
    "hideDisabled": False,
    "techniques": [
        {
            "techniqueID": "T1110",
            "color": "#fd8d3c",
            "comment": "This is a comment for technique T1110",
            "showSubtechniques": True,
        },
        {
            "techniqueID": "T1110.001",
            "comment": "This is a comment for T1110.001 - the first subtechnique of technique T1110.001",
        },
        {
            "techniqueID": "T1134",
            "tactic": "defense-evasion",
            "score": 75,
            "comment": "this is a comment for T1134 which is only applied on the defense-evasion tactic",
        },
        {"techniqueID": "T1078", "tactic": "discovery", "enabled": False},
        {
            "techniqueID": "T1053",
            "tactic": "privilege-escalation",
            "metadata": [
                {"name": "T1053 metadata1", "value": "T1053 metadata1 value"},
                {"name": "T1053 metadata2", "value": "T1053 metadata2 value"},
            ],
        },
    ],
    "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0},
    "legendItems": [{"label": "Legend Item Label", "color": "#FF00FF"}],
    "showTacticRowBackground": True,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": False,
    "metadata": [
        {"name": "layer metadata 1", "value": "layer metadata 1 value"},
        {"name": "layer metadata 2", "value": "layer metadata 2 value"},
    ],
}

example_layer_v43_dict = {
    "name": "example layer",
    "versions": {"attack": "10", "navigator": "4.5.5", "layer": "4.3"},
    "domain": "enterprise-attack",
    "description": "hello, world",
    "filters": {"platforms": ["Windows", "macOS"]},
    "sorting": 2,
    "layout": {
        "layout": "side",
        "showName": True,
        "showID": False,
        "showAggregateScores": True,
        "countUnscored": True,
        "aggregateFunction": "average",
    },
    "hideDisabled": False,
    "techniques": [
        {
            "techniqueID": "T1110",
            "score": 0,
            "color": "#fd8d3c",
            "comment": "This is a comment for technique T1110",
            "showSubtechniques": True,
        },
        {
            "techniqueID": "T1110.001",
            "score": 100,
            "comment": "This is a comment for T1110.001 - the first subtechnique of technique T1110.001",
            "links": [{"label": "Navigator GitHub", "url": "https://github.com/mitre-attack/attack-navigator"}],
        },
        {
            "techniqueID": "T1134",
            "tactic": "defense-evasion",
            "score": 75,
            "comment": "this is a comment for T1134 which is only applied on the defense-evasion tactic",
        },
        {"techniqueID": "T1078", "tactic": "discovery", "enabled": False},
        {
            "techniqueID": "T1053",
            "tactic": "privilege-escalation",
            "metadata": [
                {"name": "T1053 metadata1", "value": "T1053 metadata1 value"},
                {"divider": True},
                {"name": "T1053 metadata2", "value": "T1053 metadata2 value"},
            ],
        },
        {
            "techniqueID": "T1098",
            "tactic": "persistence",
            "score": 80,
            "links": [{"label": "Navigator GitHub", "url": "https://github.com/mitre-attack/attack-navigator"}],
        },
    ],
    "gradient": {"colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"], "minValue": 0, "maxValue": 100},
    "legendItems": [{"label": "Legend Item Label", "color": "#FF00FF"}],
    "showTacticRowBackground": True,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": False,
    "selectSubtechniquesWithParent": False,
    "selectVisibleTechniques": False,
    "metadata": [
        {"name": "layer metadata 1", "value": "layer metadata 1 value"},
        {"divider": True},
        {"name": "layer metadata 2", "value": "layer metadata 2 value"},
    ],
    "links": [],
}

example_layer_v42_dict = {
    "name": "example layer",
    "versions": {"attack": "8", "navigator": "4.4.4", "layer": "4.2"},
    "domain": "enterprise-attack",
    "description": "hello, world",
    "filters": {"platforms": ["Windows", "macOS"]},
    "sorting": 2,
    "layout": {
        "layout": "side",
        "showName": True,
        "showID": False,
        "showAggregateScores": True,
        "countUnscored": True,
        "aggregateFunction": "average",
    },
    "hideDisabled": False,
    "techniques": [
        {
            "techniqueID": "T1110",
            "score": 0,
            "color": "#fd8d3c",
            "comment": "This is a comment for technique T1110",
            "showSubtechniques": True,
        },
        {
            "techniqueID": "T1110.001",
            "score": 100,
            "comment": "This is a comment for T1110.001 - the first subtechnique of technique T1110.001",
        },
        {
            "techniqueID": "T1134",
            "tactic": "defense-evasion",
            "score": 75,
            "comment": "this is a comment for T1134 which is only applied on the defense-evasion tactic",
        },
        {"techniqueID": "T1078", "tactic": "discovery", "enabled": False},
        {
            "techniqueID": "T1053",
            "tactic": "privilege-escalation",
            "metadata": [
                {"name": "T1053 metadata1", "value": "T1053 metadata1 value"},
                {"divider": True},
                {"name": "T1053 metadata2", "value": "T1053 metadata2 value"},
            ],
        },
    ],
    "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
    "legendItems": [{"label": "Legend Item Label", "color": "#FF00FF"}],
    "showTacticRowBackground": True,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": False,
    "selectSubtechniquesWithParent": False,
    "selectVisibleTechniques": False,
    "metadata": [
        {"name": "layer metadata 1", "value": "layer metadata 1 value"},
        {"name": "layer metadata 2", "value": "layer metadata 2 value"},
    ],
}

with open("resources/collection-1.json", "r", encoding="utf-16") as input_file:
    collection = json.load(input_file)


index = {
    "id": "10296991-439b-4202-90a3-e38812613ad4",
    "name": "MITRE ATT&CK",
    "description": "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.",
    "created": "2018-01-17T12:56:55.080000+00:00",
    "modified": "2021-04-29T14:49:39.188000+00:00",
    "collections": [
        {
            "id": "x-mitre-collection--23320f4-22ad-8467-3b73-ed0c869a12838",
            "created": "2018-01-17T12:56:55.080Z",
            "versions": [
                {
                    "version": "9.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-9.0.json",
                    "modified": "2021-04-29T14:49:39.188Z",
                },
                {
                    "version": "8.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-8.2.json",
                    "modified": "2021-01-27T14:49:39.188Z",
                },
                {
                    "version": "8.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-8.1.json",
                    "modified": "2020-11-12T14:49:39.188Z",
                },
                {
                    "version": "8.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-8.0.json",
                    "modified": "2020-10-27T14:49:39.188Z",
                },
                {
                    "version": "7.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-7.2.json",
                    "modified": "2020-07-15T14:49:39.188Z",
                },
                {
                    "version": "7.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-7.1.json",
                    "modified": "2020-07-13T14:49:39.188Z",
                },
                {
                    "version": "7.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-7.0.json",
                    "modified": "2020-03-31T14:49:39.188Z",
                },
                {
                    "version": "6.3",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-6.3.json",
                    "modified": "2020-03-09T14:49:39.188Z",
                },
                {
                    "version": "6.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-6.2.json",
                    "modified": "2019-12-02T14:49:39.188Z",
                },
                {
                    "version": "6.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-6.1.json",
                    "modified": "2019-11-21T14:49:39.188Z",
                },
                {
                    "version": "6.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-6.0.json",
                    "modified": "2019-10-23T14:19:37.289Z",
                },
                {
                    "version": "5.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-5.2.json",
                    "modified": "2019-07-27T00:09:37.061Z",
                },
                {
                    "version": "5.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-5.1.json",
                    "modified": "2019-07-27T00:09:36.949Z",
                },
                {
                    "version": "5.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-5.0.json",
                    "modified": "2019-07-19T17:44:53.176Z",
                },
                {
                    "version": "4.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-4.0.json",
                    "modified": "2019-04-30T13:45:13.024Z",
                },
                {
                    "version": "3.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-3.0.json",
                    "modified": "2018-10-23T00:14:20.652Z",
                },
                {
                    "version": "2.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-2.0.json",
                    "modified": "2018-04-18T17:59:24.739Z",
                },
                {
                    "version": "1.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-1.0.json",
                    "modified": "2018-01-17T12:56:55.080Z",
                },
            ],
            "name": "Enterprise ATT&CK",
            "description": "ATT&CK for Enterprise provides a knowledge base of real-world adversary behavior targeting traditional enterprise networks. ATT&CK for Enterprise covers the following platforms: Windows, macOS, Linux, PRE, Office 365, Google Workspace, IaaS, Network, and Containers.",
        },
        {
            "id": "x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858",
            "created": "2018-01-17T12:56:55.080Z",
            "versions": [
                {
                    "version": "9.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-9.0.json",
                    "modified": "2021-04-29T14:49:39.188Z",
                },
                {
                    "version": "8.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-8.2.json",
                    "modified": "2021-01-27T14:49:39.188Z",
                },
                {
                    "version": "8.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-8.1.json",
                    "modified": "2020-11-12T14:49:39.188Z",
                },
                {
                    "version": "8.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-8.0.json",
                    "modified": "2020-10-27T14:49:39.188Z",
                },
                {
                    "version": "7.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-7.2.json",
                    "modified": "2020-07-15T14:49:39.188Z",
                },
                {
                    "version": "7.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-7.1.json",
                    "modified": "2020-07-13T14:49:39.188Z",
                },
                {
                    "version": "7.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-7.0.json",
                    "modified": "2020-03-31T14:49:39.188Z",
                },
                {
                    "version": "6.3",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-6.3.json",
                    "modified": "2020-03-09T14:49:39.188Z",
                },
                {
                    "version": "6.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-6.2.json",
                    "modified": "2019-12-02T14:49:39.188Z",
                },
                {
                    "version": "6.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-6.1.json",
                    "modified": "2019-11-21T14:49:39.188Z",
                },
                {
                    "version": "6.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-6.0.json",
                    "modified": "2019-10-23T14:19:37.289Z",
                },
                {
                    "version": "5.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-5.2.json",
                    "modified": "2019-07-27T00:09:37.061Z",
                },
                {
                    "version": "5.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-5.1.json",
                    "modified": "2019-07-27T00:09:36.949Z",
                },
                {
                    "version": "5.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-5.0.json",
                    "modified": "2019-07-19T17:44:53.176Z",
                },
                {
                    "version": "4.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-4.0.json",
                    "modified": "2019-04-30T13:45:13.024Z",
                },
                {
                    "version": "3.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-3.0.json",
                    "modified": "2018-10-23T00:14:20.652Z",
                },
                {
                    "version": "2.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-2.0.json",
                    "modified": "2018-04-18T17:59:24.739Z",
                },
                {
                    "version": "1.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-1.0.json",
                    "modified": "2018-01-17T12:56:55.080Z",
                },
            ],
            "name": "Mobile ATT&CK",
            "description": "ATT&CK for Mobile is a matrix of adversary behavior against mobile devices (smartphones and tablets running the Android or iOS/iPadOS operating systems). ATT&CK for Mobile builds upon NIST's Mobile Threat Catalogue and also contains a separate matrix of network-based effects, which are techniques that an adversary can employ without access to the mobile device itself.",
        },
        {
            "id": "x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09",
            "created": "2020-10-27T14:49:39.188Z",
            "versions": [
                {
                    "version": "9.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-9.0.json",
                    "modified": "2021-04-29T14:49:39.188Z",
                },
                {
                    "version": "8.2",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-8.2.json",
                    "modified": "2021-01-27T14:49:39.188Z",
                },
                {
                    "version": "8.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-8.1.json",
                    "modified": "2020-11-12T14:49:39.188Z",
                },
                {
                    "version": "8.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-8.0.json",
                    "modified": "2020-10-27T14:49:39.188Z",
                },
            ],
            "name": "ICS ATT&CK",
            "description": "The ATT&CK for Industrial Control Systems (ICS) knowledge base categorizes the unique set of tactics, techniques, and procedures (TTPs) used by threat actors in the ICS technology domain. ATT&CK for ICS outlines the portions of an ICS attack that are out of scope of Enterprise and reflects the various phases of an adversary\u2019s attack life cycle and the assets and systems they are known to target.",
        },
    ],
}
