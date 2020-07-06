from arches.app.models.models import Node, TileModel
from arches.app.models.system_settings import settings
from guardian.backends import check_support
from guardian.backends import ObjectPermissionBackend
from django.core.exceptions import ObjectDoesNotExist
from guardian.core import ObjectPermissionChecker
from guardian.shortcuts import (
    get_perms,
    get_objects_for_user,
    get_group_perms,
    get_user_perms,
    get_users_with_perms,
    remove_perm,
    assign_perm,
)
from guardian.exceptions import WrongAppError
from django.contrib.auth.models import Group, Permission
import logging
from arches.app.models.models import ResourceInstance, GraphModel
from arches.app.search.search_engine_factory import SearchEngineFactory
from arches.app.search.elasticsearch_dsl_builder import Bool, Query, Terms
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

class PermissionBackend(ObjectPermissionBackend):
    def has_perm(self, user_obj, perm, obj=None):
        # check if user_obj and object are supported (pulled directly from guardian)
        support, user_obj = check_support(user_obj, obj)
        if not support:
            return False

        if "." in perm:
            app_label, perm = perm.split(".")
            if app_label != obj._meta.app_label:
                raise WrongAppError("Passed perm has app label of '%s' and " "given obj has '%s'" % (app_label, obj._meta.app_label))

        explicitly_defined_perms = get_perms(user_obj, obj)
        if len(explicitly_defined_perms) > 0:
            if "no_access_to_nodegroup" in explicitly_defined_perms:
                return False
            else:
                return perm in explicitly_defined_perms
        else:
            default_perms = []
            for group in user_obj.groups.all():
                for permission in group.permissions.all():
                    if perm in permission.codename:
                        return True
            return False


def get_restricted_users(resource):
    """
    Takes a resource instance and identifies which users are explicitly restricted from
    reading, editing, deleting, or accessing it.

    """

    user_perms = get_users_with_perms(resource, attach_perms=True, with_group_users=False)
    user_and_group_perms = get_users_with_perms(resource, attach_perms=True, with_group_users=True)

    result = {
        "no_access": [],
        "cannot_read": [],
        "cannot_write": [],
        "cannot_delete": [],
    }

    for user, perms in user_and_group_perms.items():
        if user.is_superuser:
            pass
        elif user in user_perms and "no_access_to_resourceinstance" in user_perms[user]:
            for k, v in result.items():
                v.append(user.id)
        else:
            if "view_resourceinstance" not in perms:
                result["cannot_read"].append(user.id)
            if "change_resourceinstance" not in perms:
                result["cannot_write"].append(user.id)
            if "delete_resourceinstance" not in perms:
                result["cannot_delete"].append(user.id)
            if "no_access_to_resourceinstance" in perms and len(perms) == 1:
                result["no_access"].append(user.id)

    return result


def get_restricted_instances(user):
    if user.is_superuser is False:
        se = SearchEngineFactory().create()
        query = Query(se, start=0, limit=settings.SEARCH_RESULT_LIMIT)
        has_access = Bool()
        terms = Terms(field="permissions.users_with_no_access", terms=[str(user.id)])
        has_access.must(terms)
        query.add_query(has_access)
        results = query.search(index="resources", scroll="1m")
        scroll_id = results["_scroll_id"]
        total = results["hits"]["total"]["value"]
        if total > settings.SEARCH_RESULT_LIMIT:
            pages = total // settings.SEARCH_RESULT_LIMIT
            for page in range(pages):
                results_scrolled = query.se.es.scroll(scroll_id=scroll_id, scroll="1m")
                results["hits"]["hits"] += results_scrolled["hits"]["hits"]
        restricted_ids = [res["_id"] for res in results["hits"]["hits"]]
        return restricted_ids
    else:
        return []


def get_groups_for_object(perm, obj):
    """
    returns a list of group objects that have the given permission on the given object

    Arguments:
    perm -- the permssion string eg: "read_nodegroup"
    obj -- the model instance to check

    """

    def has_group_perm(group, perm, obj):
        explicitly_defined_perms = get_perms(group, obj)
        if len(explicitly_defined_perms) > 0:
            if "no_access_to_nodegroup" in explicitly_defined_perms:
                return False
            else:
                return perm in explicitly_defined_perms
        else:
            default_perms = []
            for permission in group.permissions.all():
                if perm in permission.codename:
                    return True
            return False

    ret = []
    for group in Group.objects.all():
        if has_group_perm(group, perm, obj):
            ret.append(group)
    return ret


def get_users_for_object(perm, obj):
    """
    returns a list of user objects that have the given permission on the given object

    Arguments:
    perm -- the permssion string eg: "read_nodegroup"
    obj -- the model instance to check

    """

    ret = []
    for user in get_user_model().objects.all():
        if user.has_perm(perm, obj):
            ret.append(user)
    return ret


def get_nodegroups_by_perm(user, perms, any_perm=True):
    """
    returns a list of node groups that a user has the given permission on

    Arguments:
    user -- the user to check
    perms -- the permssion string eg: "read_nodegroup" or list of strings
    any_perm -- True to check ANY perm in "perms" or False to check ALL perms

    """

    A = set(
        get_objects_for_user(
            user,
            ["models.read_nodegroup", "models.write_nodegroup", "models.delete_nodegroup", "models.no_access_to_nodegroup"],
            accept_global_perms=False,
            any_perm=True,
        )
    )
    B = set(get_objects_for_user(user, perms, accept_global_perms=False, any_perm=any_perm))
    C = set(get_objects_for_user(user, perms, accept_global_perms=True, any_perm=any_perm))
    return list(C - A | B)


def get_readable_resource_types(user):
     """
     returns a list of graphs that a user can read resource instances of

     Arguments:
     user -- the user to check

     """

     return get_resource_types_by_perm(user, ['models.read_nodegroup'])


def get_editable_resource_types(user):
    """
    returns a list of graphs of which a user can edit resource instances

    Arguments:
    user -- the user to check

    """

    return get_resource_types_by_perm(user, ["models.write_nodegroup", "models.delete_nodegroup"])


def get_createable_resource_types(user):
    """
    returns a list of graphs of which a user can create resource instances

    Arguments:
    user -- the user to check

    """

    return get_resource_types_by_perm(user, "models.write_nodegroup")


def user_can_edit_graph(user, graphid):
    """
    returns true if a user can edit a graph

    Arguments:
    user -- the user to check
    graphid -- the graph id

    """
    
    perm_manager = RoleGraphPermissions()
    return perm_manager.has_role_permissions(user, graphid, ["models.write_nodegroup", "models.delete_nodegroup"])


def get_resource_types_by_perm(user, perms):
    """
    returns a list of graphs for which a user has specific node permissions

    Arguments:
    user -- the user to check
    perms -- the permssion string eg: "read_nodegroup" or list of strings
    resource -- a resource instance to check if a user has permissions to that resource's type specifically

    """

    graphs = set()
    perm_manager = RoleGraphPermissions()

    for graph in GraphModel.objects.filter(isresource=True):
        if str(graph.graphid) != settings.SYSTEM_SETTINGS_RESOURCE_MODEL_ID:
            has_perm = perm_manager.has_role_permissions(user, graph.graphid, perms)
            if has_perm is None or has_perm:
                graphs.add(graph)
    return list(graphs)


def user_can_edit_model_nodegroups(user, resource):
    """
    returns a list of graphs of which a user can edit resource instances

    Arguments:
    user -- the user to check
    resource -- an instance of a model

    """

    return user_has_resource_model_permissions(user, ["models.write_nodegroup"], resource)


def user_can_delete_model_nodegroups(user, resource):
    """
    returns a list of graphs of which a user can edit resource instances

    Arguments:
    user -- the user to check
    resource -- an instance of a model

    """

    return user_has_resource_model_permissions(user, ["models.delete_nodegroup"], resource)


def user_has_resource_model_permissions(user, perms, resource):
    """
    Checks if a user has any explicit permissions to a model's nodegroups

    Arguments:
    user -- the user to check
    perms -- the permssion string eg: "read_nodegroup" or list of strings
    resource -- a resource instance to check if a user has permissions to that resource's type specifically

    """

    nodegroups = get_nodegroups_by_perm(user, perms)
    nodes = Node.objects.filter(nodegroup__in=nodegroups).filter(graph_id=resource.graph_id).select_related("graph")
    return nodes.count() > 0


def check_resource_instance_permissions(user, resourceid, permission):
    """
    Checks if a user has permission to access a resource instance

    Arguments:
    user -- the user to check
    resourceid -- the id of the resource
    permission -- the permission codename (e.g. 'view_resourceinstance') for which to check

    """
    result = {}
    try:
        resource = ResourceInstance.objects.get(resourceinstanceid=resourceid)
        result["resource"] = resource

        all_perms = []
        #get role permissions first
        if not user.is_superuser:
            all_perms = get_role_permissions_for_resource(user, resource)

        if len(all_perms) == 0:
            #get user resource native permissions
            all_perms = get_perms(user, resource)

        if len(all_perms) == 0:  # no permissions assigned. permission implied
            result["permitted"] = "unknown"
            return result
        else:
            # check role permissions
            if "no_access_to_resourceinstance" in all_perms:  # user is restricted
                result["permitted"] = False
                return result
            elif permission in all_perms:  # user is permitted
                result["permitted"] = True
                return result

            user_permissions = get_user_perms(user, resource)
            if "no_access_to_resourceinstance" in user_permissions:  # user is restricted
                result["permitted"] = False
                return result
            elif permission in user_permissions:  # user is permitted
                result["permitted"] = True
                return result

            group_permissions = get_group_perms(user, resource)
            if "no_access_to_resourceinstance" in group_permissions:  # group is restricted - no user override
                result["permitted"] = False
                return result
            elif permission in group_permissions:  # group is permitted - no user override
                result["permitted"] = True
                return result

            if permission not in all_perms:  # neither user nor group explicitly permits or restricts.
                result["permitted"] = False  # restriction implied
                return result

    except ObjectDoesNotExist:
        return None

    return result


def user_can_read_resource(user, resourceid=None):
    """
    Requires that a user be able to read an instance and read a single nodegroup of a resource

    """

    if user.is_authenticated:
        if user.is_superuser:
            return True
        if resourceid not in [None, ""]:
            result = check_resource_instance_permissions(user, resourceid, "view_resourceinstance")
            if result is not None:
                if result["permitted"] == "unknown":
                    return user_has_resource_model_permissions(user, ["models.read_nodegroup"], result["resource"])
                else:
                    return result["permitted"]
            else:
                return None

        return len(get_resource_types_by_perm(user, ["models.read_nodegroup"])) > 0
    return False


def user_can_edit_resource(user, resourceid=None):
    """
    Requires that a user be able to edit an instance and delete a single nodegroup of a resource

    """

    if user.is_authenticated:
        if user.is_superuser:
            return True
        if resourceid not in [None, ""]:
            result = check_resource_instance_permissions(user, resourceid, "change_resourceinstance")
            if result is not None:
                if result["permitted"] == "unknown":
                    return user.groups.filter(name__in=settings.RESOURCE_EDITOR_GROUPS).exists() or user_can_edit_model_nodegroups(
                        user, result["resource"]
                    )
                else:
                    return result["permitted"]
            else:
                return None

        return user.groups.filter(name__in=settings.RESOURCE_EDITOR_GROUPS).exists() or len(get_editable_resource_types(user)) > 0
    return False


def user_can_delete_resource(user, resourceid=None):
    """
    Requires that a user be permitted to delete an instance

    """
    if user.is_authenticated:
        if user.is_superuser:
            return True
        if resourceid not in [None, ""]:
            result = check_resource_instance_permissions(user, resourceid, "delete_resourceinstance")
            if result is not None:
                if result["permitted"] == "unknown":
                    nodegroups = get_nodegroups_by_perm(user, "models.delete_nodegroup")
                    tiles = TileModel.objects.filter(resourceinstance_id=resourceid)
                    protected_tiles = {str(tile.nodegroup_id) for tile in tiles} - {str(nodegroup.nodegroupid) for nodegroup in nodegroups}
                    if len(protected_tiles) > 0:
                        return False
                    return user.groups.filter(name__in=settings.RESOURCE_EDITOR_GROUPS).exists() or user_can_delete_model_nodegroups(
                        user, result["resource"]
                    )
                else:
                    return result["permitted"]
            else:
                return None
    return False


def user_can_read_concepts(user):
    """
    Requires that a user is a part of the RDM Administrator group

    """

    if user.is_authenticated:
        return user.groups.filter(name="RDM Administrator").exists()
    return False


def user_is_resource_reviewer(user):
    """
    Single test for whether a user is in the Resource Reviewer group
    """

    return user.groups.filter(name='Resource Reviewer').exists()


def get_role_permissions_for_resource(user, resource):
    from arches.app.models.models import AuthRole
    from arches.app.models.resource import Resource
    results = set()
    # check if the user is an external for all the resources except heritage
    if str(resource.graph_id) != settings.HERITAGE_GRAPH_ID and user.groups.filter(name=settings.EXTERNALS_GROUP).exists():
        from arches.app.views.resource import get_instance_creator
        creator = get_instance_creator(resource)
        # each external user can only see his own resouce instances
        if creator['creatorid'] != str(user.id):
            results.add('no_access_to_resourceinstance')
            return list(results)

    try:
        # two types of resource objects are handled Resource and ResourceInstance
        if getattr(resource, 'get_node_values', None) is None:
            resource = Resource.objects.get(pk=resource.resourceinstanceid)

        heritageId, areaId = resource.resolve_resource_area()

        if heritageId is not None and areaId is not None:
            graphid = resource.graph_id

            #raw query must be executed in order to join tables referring to a common
            #external table (auth_group)
            query = 'select ar.auth_role_id, ar.permission, ar.auth_group_id, ar.graph_id '\
                    'from models_authrole ar join models_arearole ro '\
                    'on ar.auth_group_id = ro.auth_group_id where ' \
                    'ar.graph_id = UUID(\'' + str(graphid) + '\') and ro.user_id = ' + str(user.id) + ' ' \
                    'and (ro.resource_instance_id = UUID(\'' + heritageId + '\') or ro.area_id=UUID(\'' + areaId + '\'))'

            perms = AuthRole.objects.raw(query)

            # no access without permissions
            if len(perms) == 0:
                results.add('no_access_to_resourceinstance')

            #a user can have multiple roles on the same area or heritage resource
            #remove the "no access" permission if another permission is available

            has_no_access = False
            for perm in perms:
                if perm.WRITE_ == perm.permission:
                    results.add('change_resourceinstance')
                    results.add('view_resourceinstance')
                elif perm.READ_ == perm.permission:
                    results.add('view_resourceinstance')
                elif perm.NO_ACCESS_ == perm.permission:
                    has_no_access = True
                elif perm.DELETE_ == perm.permission:
                    results.add('delete_resourceinstance')
                    results.add('change_resourceinstance')
                    results.add('view_resourceinstance')

            if has_no_access and len(results) == 0:
                results.add('no_access_to_resourceinstance')

    except Exception as e:
        logger.exception(e)

    return list(results)



def get_role_permissions_for_user(user):
    from arches.app.models.models import AreaRole, AuthRole

    def get_validations(auth_group):
        validations = []
        if auth_group.validate_decay:
            validations.append(settings.VALIDATION_TYPES[0])
        if auth_group.validate_instability:
            validations.append(settings.VALIDATION_TYPES[1])
        if auth_group.validate_vegetation:
            validations.append(settings.VALIDATION_TYPES[2])
        return validations

    permitted_instances = []
    permitted_areas = []

    user_roles = AreaRole.objects.filter(user=user)
    for role in user_roles:
        auth_group = role.auth_group
        if role.resource_instance is not None:
            role_perms = AuthRole.objects.filter(auth_group=auth_group)
            for perm in role_perms:
                if perm.NO_ACCESS_ != perm.permission:
                    permitted_instances.append((str(role.resource_instance_id), str(perm.graph.graphid), get_validations(auth_group)))
        elif role.area is not None:
            role_perms = AuthRole.objects.filter(auth_group=auth_group)
            for perm in role_perms:
                if perm.NO_ACCESS_ != perm.permission:
                    permitted_areas.append((str(role.area.valueid), str(perm.graph.graphid), get_validations(auth_group)))


    return permitted_areas, permitted_instances


class RoleGraphPermissions(object):
    def __init__(self):
        self._perms_cache = {}

    def has_role_permissions(self, user, graphid, permissions):
        from arches.app.models.models import AuthRole

        if user.is_superuser:
            return True
        has_role = False
        try:
            graphid = str(graphid)
            userid = str(user.id)
            key = graphid + userid

            if not key in self._perms_cache:
                #raw query must be executed in order to join tables referring to a common
                #external table (auth_group)
                query = 'select ar.auth_role_id, ar.permission, ar.auth_group_id, ar.graph_id '\
                        'from models_authrole ar join models_arearole ro '\
                        'on ar.auth_group_id = ro.auth_group_id where ' \
                        'ar.graph_id = UUID(\'' + graphid + '\') and ro.user_id = ' + userid

                perms = AuthRole.objects.raw(query)
                self._perms_cache[key] = perms
            else:
                perms = self._perms_cache[key]

            if isinstance(permissions, str):
                permissions = [permissions]

            for permission in permissions:
                if not permission.startswith('models.'):
                    return None

                for perm in perms:
                    #if permission == "models." + perm.PERMISSIONS[perm.permission]:
                    #    return True

                    stored = perm.PERMISSIONS[perm.permission]
                    if permission == "models." + perm.DELETE and stored == perm.DELETE:
                        return True
                    elif permission == "models." + perm.WRITE and \
                            (stored == perm.WRITE or stored == perm.DELETE):
                        return True
                    elif permission == "models." + perm.READ and \
                            (stored == perm.WRITE or stored == perm.DELETE or stored == perm.READ):
                        return True


        except Exception as e:
            logger.exception(e)
            has_role = False

        return has_role