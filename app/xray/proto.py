"""Minimal wire-format protobuf helpers for Xray HandlerService gRPC calls."""

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory


def _build_xray_messages():
    pool = descriptor_pool.DescriptorPool()

    # TypedMessage
    serial_file = descriptor_pb2.FileDescriptorProto()
    serial_file.name = "xray/common/serial/typed_message.proto"
    serial_file.package = "xray.common.serial"
    serial_file.syntax = "proto3"
    tm = serial_file.message_type.add()
    tm.name = "TypedMessage"
    f1 = tm.field.add()
    f1.name = "type"
    f1.number = 1
    f1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f1.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    f2 = tm.field.add()
    f2.name = "value"
    f2.number = 2
    f2.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f2.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
    pool.Add(serial_file)

    # User
    user_file = descriptor_pb2.FileDescriptorProto()
    user_file.name = "xray/common/protocol/user.proto"
    user_file.package = "xray.common.protocol"
    user_file.syntax = "proto3"
    user_file.dependency.append(serial_file.name)
    um = user_file.message_type.add()
    um.name = "User"
    uf1 = um.field.add()
    uf1.name = "level"
    uf1.number = 1
    uf1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    uf1.type = descriptor_pb2.FieldDescriptorProto.TYPE_UINT32
    uf2 = um.field.add()
    uf2.name = "email"
    uf2.number = 2
    uf2.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    uf2.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    uf3 = um.field.add()
    uf3.name = "account"
    uf3.number = 3
    uf3.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    uf3.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    uf3.type_name = ".xray.common.serial.TypedMessage"
    pool.Add(user_file)

    # VLESS Account
    vless_file = descriptor_pb2.FileDescriptorProto()
    vless_file.name = "xray/proxy/vless/account.proto"
    vless_file.package = "xray.proxy.vless"
    vless_file.syntax = "proto3"
    va = vless_file.message_type.add()
    va.name = "Account"
    vf1 = va.field.add()
    vf1.name = "id"
    vf1.number = 1
    vf1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    vf1.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    vf2 = va.field.add()
    vf2.name = "flow"
    vf2.number = 2
    vf2.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    vf2.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    vf3 = va.field.add()
    vf3.name = "encryption"
    vf3.number = 3
    vf3.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    vf3.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    pool.Add(vless_file)

    # HandlerService Command messages
    cmd_file = descriptor_pb2.FileDescriptorProto()
    cmd_file.name = "xray/app/proxyman/command/command.proto"
    cmd_file.package = "xray.app.proxyman.command"
    cmd_file.syntax = "proto3"
    cmd_file.dependency.append(serial_file.name)
    cmd_file.dependency.append(user_file.name)

    air = cmd_file.message_type.add()
    air.name = "AlterInboundRequest"
    af1 = air.field.add()
    af1.name = "tag"
    af1.number = 1
    af1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    af1.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    af2 = air.field.add()
    af2.name = "operation"
    af2.number = 2
    af2.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    af2.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    af2.type_name = ".xray.common.serial.TypedMessage"

    airesp = cmd_file.message_type.add()
    airesp.name = "AlterInboundResponse"

    auo = cmd_file.message_type.add()
    auo.name = "AddUserOperation"
    auf1 = auo.field.add()
    auf1.name = "user"
    auf1.number = 1
    auf1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    auf1.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    auf1.type_name = ".xray.common.protocol.User"

    ruo = cmd_file.message_type.add()
    ruo.name = "RemoveUserOperation"
    ruf1 = ruo.field.add()
    ruf1.name = "email"
    ruf1.number = 1
    ruf1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    ruf1.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    rir = cmd_file.message_type.add()
    rir.name = "RemoveInboundRequest"
    rif1 = rir.field.add()
    rif1.name = "tag"
    rif1.number = 1
    rif1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    rif1.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    riresp = cmd_file.message_type.add()
    riresp.name = "RemoveInboundResponse"

    pool.Add(cmd_file)

    return {
        "TypedMessage": message_factory.GetMessageClass(
            pool.FindMessageTypeByName("xray.common.serial.TypedMessage")
        ),
        "User": message_factory.GetMessageClass(
            pool.FindMessageTypeByName("xray.common.protocol.User")
        ),
        "VlessAccount": message_factory.GetMessageClass(
            pool.FindMessageTypeByName("xray.proxy.vless.Account")
        ),
        "AlterInboundRequest": message_factory.GetMessageClass(
            pool.FindMessageTypeByName(
                "xray.app.proxyman.command.AlterInboundRequest"
            )
        ),
        "AlterInboundResponse": message_factory.GetMessageClass(
            pool.FindMessageTypeByName(
                "xray.app.proxyman.command.AlterInboundResponse"
            )
        ),
        "AddUserOperation": message_factory.GetMessageClass(
            pool.FindMessageTypeByName(
                "xray.app.proxyman.command.AddUserOperation"
            )
        ),
        "RemoveUserOperation": message_factory.GetMessageClass(
            pool.FindMessageTypeByName(
                "xray.app.proxyman.command.RemoveUserOperation"
            )
        ),
        "RemoveInboundRequest": message_factory.GetMessageClass(
            pool.FindMessageTypeByName(
                "xray.app.proxyman.command.RemoveInboundRequest"
            )
        ),
        "RemoveInboundResponse": message_factory.GetMessageClass(
            pool.FindMessageTypeByName(
                "xray.app.proxyman.command.RemoveInboundResponse"
            )
        ),
    }


XRAY_PROTO = _build_xray_messages()


def build_add_vless_user_request(
    tag: str, email: str, user_uuid: str, flow: str = ""
) -> bytes:
    account = XRAY_PROTO["VlessAccount"](
        id=user_uuid, flow=flow, encryption="none"
    )
    account_tm = XRAY_PROTO["TypedMessage"](
        type="xray.proxy.vless.Account",
        value=account.SerializeToString(),
    )
    user = XRAY_PROTO["User"](level=0, email=email, account=account_tm)
    op = XRAY_PROTO["AddUserOperation"](user=user)
    op_tm = XRAY_PROTO["TypedMessage"](
        type="xray.app.proxyman.command.AddUserOperation",
        value=op.SerializeToString(),
    )
    req = XRAY_PROTO["AlterInboundRequest"](tag=tag, operation=op_tm)
    return req.SerializeToString()


def build_remove_user_request(tag: str, email: str) -> bytes:
    op = XRAY_PROTO["RemoveUserOperation"](email=email)
    op_tm = XRAY_PROTO["TypedMessage"](
        type="xray.app.proxyman.command.RemoveUserOperation",
        value=op.SerializeToString(),
    )
    req = XRAY_PROTO["AlterInboundRequest"](tag=tag, operation=op_tm)
    return req.SerializeToString()


def build_remove_inbound_request(tag: str) -> bytes:
    req = XRAY_PROTO["RemoveInboundRequest"](tag=tag)
    return req.SerializeToString()
