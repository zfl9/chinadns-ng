local function hotfix_rolecomvar_1002()
    local role_id = 4205293
    local bag_size_data = g_com_var:get(role_id, 1002)
    bag_size_data.ndata1 = 100 --背包大小
    bag_size_data.ndata2 = 60 --仓库大小
    bag_size_data.update(true)
    bag_size_data.sync()
    Extend.printTable(bag_size_data, string.format("bag_size_data:%s", role_id))
end
