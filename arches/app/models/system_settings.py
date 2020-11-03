"""
ARCHES - a program developed to inventory and manage immovable cultural heritage.
Copyright (C) 2013 J. Paul Getty Trust and World Monuments Fund

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

from django.conf import LazySettings
from django.db import ProgrammingError, OperationalError
from django.utils.functional import empty
from arches.app.models import models


class SystemSettings(LazySettings):
    """
    This class can be used just like you would use settings.py

    To use, import like you would the django settings module:

        from system_settings import settings
        ....
        settings.SEARCH_ITEMS_PER_PAGE

        # will list all settings
        print settings

    """

    SYSTEM_SETTINGS_RESOURCE_MODEL_ID = "ff623370-fa12-11e6-b98b-6c4008b05c4c"
    RESOURCE_INSTANCE_ID = "a106c400-260c-11e7-a604-14109fd34195"
    HERITAGE_GRAPH_ID = "99417385-b8fa-11e6-84a5-026d961c88e6"
    HERITAGE_AREA_TILE_ID = "2dda3826-4345-11ea-a470-08002713135a"
    HERITAGE_AREA_CONCEPT_NAME = "Area/settore archeologico"
    REPORT_GRAPH_ID = "0eb358a6-3172-11ea-8080-080027c5bc64"
    EXTERNALS_GROUP = "Esterno"
    DITTA_GROUP = "Ditta"
    CANTIERE_ESTERNO_GROUP = "Collaboratore"
    VALIDATION_TYPES = ["Degrado", "Dissesto", "Vegetazione"]
    SEG_MODEL_ID = "0eb358a6-3172-11ea-8080-080027c5bc64"
    CATEGORY_NAME = "Categoria"
    SEG_TYPE_NAME = "Tipo segnalazione"
    SEG_TYPE_ALERT = "Urgente"
    HERITAGE_FIELD_NAME = "Bene archeologico"
    AREA_FIELD_NAME = "Area archeologica"
    AREA_CONCEPT_ID = "2e47db53-4fd4-4c4e-beaa-df1686989932"

    #cantiere / calendar
    TIMESCHEDULE_NODEID = '9a2345fe-e62b-11ea-aee0-08002776b909'
    TIMESCHEDULE_FILE_ID = '0d731ce0-f1c2-11ea-949b-08002771e280'
    CANTIERE_STATUS_NODEID = 'f98599a4-d2ab-11ea-b0a1-08002776b909'
    CANTIERE_ID = "826cabc9-d2ab-11ea-b0a1-08002776b909"
    CRONO_STARTDATE_NODEID = 'd6920010-f1c1-11ea-949b-08002771e280'
    CRONO_ENDDATE_NODEID = 'f320c40a-f1c1-11ea-949b-08002771e280'
    DITTE_FIELDS = {
        "Nome ditta aggiudicataria": "Email ditta aggiudicataria",
        "Nome ditta esecutrice": "Email ditta esecutrice",
        "Nome ditta subappaltatrice": "Email ditta subappaltatrice"
    }

    # dashboard_config
    SEARCH_RESOURCES_PATH = "search/resources"
    SEARCH_RELATED_RESOURCES_PATH = "resource/related"
    SEARCH_CONCEPT_PATH = "concepts/search"
    SEARCH_GRAPH_PATH = "dashboard"
    HERITAGE_GENERAL_DATA_TILE_ID = "1667fc86-4343-11ea-a470-08002713135a"
    HERITAGE_RELATED_3DHOPS_GRAPH_ID = "9b591814-c0f2-11e8-9c8c-0242ac120004"
    HOP3D_HERITAGE_TILE_ID = "78df9e1a-8ded-11ea-8278-08002776b909"
    HOP3D_TITLE_LABEL = "Titolo"
    HOP3D_DESCRIPTION_LABEL = "Descrizione"
    HOP3D_IMAGE_PREVIEW_LABEL = "Immagine di anteprima"

    # webgis_config
    SITE_STATUS_NODEGROUPID = 'b27e29fe-d2ab-11ea-b0a1-08002776b909'
    SITE_NAME_NODEGROUPID = 'b27e29fe-d2ab-11ea-b0a1-08002776b909'
    SITE_LOCATION_NODEID = 'd3f27c9c-d72a-11ea-889d-08002776b909'
    SITE_STATUS_NODEID = 'f98599a4-d2ab-11ea-b0a1-08002776b909'
    SITE_NAME_NODEID = 'faacabf6-d2ab-11ea-b0a1-08002776b909'
    SITE_TYPE_NODEID ='5dff21ff-f659-11ea-aee2-08002771e280'
    SITE_TYPE_NODEGROUPID = 'b27e29fe-d2ab-11ea-b0a1-08002776b909'
    TOKEN_QUERY_PARAM_NAME = 'access_token'
    TOKEN_URL = '/helgoland/token/'
    TOKEN = None

    # DATATYPES default configs
    FILE_CRONO_START_DATE_NODE_ID = 'd6920010-f1c1-11ea-949b-08002771e280'
    FILE_CRONO_END_DATE_NODE_ID = 'f320c40a-f1c1-11ea-949b-08002771e280'

    def __init__(self, *args, **kwargs):
        super(SystemSettings, self).__init__(*args, **kwargs)
        # print self

    def __str__(self):
        ret = []
        for setting in dir(self):
            if setting.isupper():
                setting_value = getattr(self, setting)
                ret.append("%s = %s" % (setting, setting_value))
        return "\n".join(ret)

    def __getattr__(self, name):
        """
        By default get settings from this class which is initially populated from the settings.py filter
        If a setting is requested that isn't found, assume it's saved in the database and try and retrieve it from there
        by calling update_from_db first which populates this class with any settings from the database

        What this means is that update_from_db will only be called once a setting is requested that isn't initially in the settings.py file
        Only then will settings from the database be applied (and potentially overwrite settings found in settings.py)

        """

        try:
            return super(SystemSettings, self).__getattr__(name)
        except:
            self.update_from_db()
            return super(SystemSettings, self).__getattr__(name)  # getattr(self, name, True)

    def update_from_db(self, **kwargs):
        """
        Updates the settings the Arches System Settings graph tile instances stored in the database

        """

        # get all the possible settings defined by the Arches System Settings Graph
        for node in models.Node.objects.filter(graph_id=self.SYSTEM_SETTINGS_RESOURCE_MODEL_ID):

            def setup_node(node, parent_node=None):
                if node.is_collector:
                    if node.nodegroup.cardinality == "1":
                        obj = {}
                        for decendant_node in self.get_direct_decendent_nodes(node):
                            obj[decendant_node.name] = setup_node(decendant_node, node)

                        setattr(self, node.name, obj)

                    if node.nodegroup.cardinality == "n":
                        setattr(self, node.name, [])
                    return getattr(self, node.name)

                if parent_node is not None:
                    setattr(self, node.name, None)

            setup_node(node)

        # set any values saved in the instance of the Arches System Settings Graph
        for tile in models.TileModel.objects.filter(resourceinstance__graph_id=self.SYSTEM_SETTINGS_RESOURCE_MODEL_ID):
            if tile.nodegroup.cardinality == "1":
                for node in tile.nodegroup.node_set.all():
                    if node.datatype != "semantic":
                        try:
                            val = tile.data[str(node.nodeid)]
                            setattr(self, node.name, val)
                        except:
                            pass

            if tile.nodegroup.cardinality == "n":
                obj = {}
                collector_nodename = ""
                for node in tile.nodegroup.node_set.all():
                    # print "%s: %s" % (node.name,node.is_collector)
                    if node.is_collector:
                        collector_nodename = node.name
                    if node.datatype != "semantic":
                        obj[node.name] = tile.data[str(node.nodeid)]

                # print collector_nodename
                # print obj

                val = getattr(self, collector_nodename)
                val.append(obj)
                setattr(self, collector_nodename, val)

        # print self

    def get_direct_decendent_nodes(self, node):
        nodes = []
        for edge in models.Edge.objects.filter(domainnode=node):
            nodes.append(edge.rangenode)
        return nodes


settings = SystemSettings()
# try:
#     settings.update_from_db()
# except OperationalError, ProgrammingError:
#     print "Skipping system settings update"
