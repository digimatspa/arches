from arches.app.models.models import Node
from arches.app.models.system_settings import settings
from guardian.backends import check_support
from guardian.backends import ObjectPermissionBackend
from django.core.exceptions import ObjectDoesNotExist
from guardian.core import ObjectPermissionChecker
from guardian.shortcuts import get_perms, get_objects_for_user, get_group_perms, get_user_perms
from guardian.exceptions import WrongAppError
from django.contrib.auth.models import User, Group, Permission
from arches.app.models.models import ResourceInstance


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
    for user in User.objects.all():
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


def get_resource_types_by_perm(user, perms):
    """
    returns a list of graphs for which a user has specific node permissions

    Arguments:
    user -- the user to check
    perms -- the permssion string eg: "read_nodegroup" or list of strings
    resource -- a resource instance to check if a user has permissions to that resource's type specifically

    """

    graphs = set()
    nodegroups = get_nodegroups_by_perm(user, perms)
    for node in Node.objects.filter(nodegroup__in=nodegroups).select_related("graph"):
        if node.graph.isresource and str(node.graph_id) != settings.SYSTEM_SETTINGS_RESOURCE_MODEL_ID:
            graphs.add(node.graph)
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
        all_perms = get_perms(user, resource)
        if len(all_perms) == 0:  # no permissions assigned. permission implied
            result["permitted"] = "unknown"
            return result
        else:
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


def user_can_read_resources(user, resourceid=None):
    """
    Requires that a user be able to read an instance and read a single nodegroup of a resource

    """
    if user.is_authenticated:
        if user.is_superuser:
            return True
        if resourceid is not None:
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


def user_can_edit_resources(user, resourceid=None):
    """
    Requires that a user be able to edit an instance and delete a single nodegroup of a resource

    """
    if user.is_authenticated:
        if user.is_superuser:
            return True
        if resourceid is not None:
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


def user_can_delete_resources(user, resourceid=None):
    """
    Requires that a user be permitted to delete an instance

    """
    if user.is_authenticated:
        if user.is_superuser:
            return True
        if resourceid is not None:
            result = check_resource_instance_permissions(user, resourceid, "delete_resourceinstance")
            if result is not None:
                if result["permitted"] == "unknown":
                    return user.groups.filter(name__in=settings.RESOURCE_EDITOR_GROUPS).exists() or user_can_edit_model_nodegroups(
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
